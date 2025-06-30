// SPDX-License-Identifier: GPL-2.0
/*
 * DAMON Primitives for Virtual Address Spaces
 *
 * Author: SeongJae Park <sjpark@amazon.de>
 */

#define pr_fmt(fmt) "damon-va: " fmt

#include <asm-generic/mman-common.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>
#include <linux/pagewalk.h>
#include <linux/sched/mm.h>

#include "ops-common.h"

// For using hypercall
#include <linux/kvm_para.h>

#ifdef CONFIG_DAMON_VADDR_KUNIT_TEST
#undef DAMON_MIN_REGION
#define DAMON_MIN_REGION 1
#endif

//	struct perf_event_attr attr_cycles = {
//	        .type = PERF_TYPE_HARDWARE,
//		.config = PERF_COUNT_HW_CPU_CYCLES,
//	        .size = sizeof(struct perf_event_attr),
//	        .disabled = 1,
//		//	.inherit = 1,
//		//	.inherit_thread = 1,
//	        .exclude_kernel = 0,
//		.exclude_user = 0,
//	        .exclude_hv = 1,
//	};
//	
//	struct perf_event_attr attr_instrs = {
//	        .type = PERF_TYPE_HARDWARE,
//	        .config = PERF_COUNT_HW_INSTRUCTIONS,
//	        .size = sizeof(struct perf_event_attr),
//	        .disabled = 1,
//		//	.inherit = 1,
//		//	.inherit_thread = 1,
//	        .exclude_kernel = 0,
//		.exclude_user = 0,
//	        .exclude_hv = 1,
//	};

struct perf_event_attr attr_cycles = {
        .type = PERF_TYPE_RAW,
	// DTLB_LOAD_MISSES.WALK_COMPLETED_4K
        .config = (0x02 << 8) | 0x08,
        .size = sizeof(struct perf_event_attr),
        .disabled = 1,
        .exclude_kernel = 0,
	.exclude_user = 0,
        .exclude_hv = 1,
};

struct perf_event_attr attr_cycles1 = {
        .type = PERF_TYPE_RAW,
	// DTLB_STORE_MISSES.WALK_COMPLETED_4K
        .config = (0x02 << 8) | 0x49,
        .size = sizeof(struct perf_event_attr),
        .disabled = 1,
        .exclude_kernel = 0,
	.exclude_user = 0,
        .exclude_hv = 1,
};

struct perf_event_attr attr_instrs = {
        .type = PERF_TYPE_RAW,
	// DTLB_LOAD_MISSES.WALK_COMPLETED_2M_4M
        .config = (0x04 << 8) | 0x08,
        .size = sizeof(struct perf_event_attr),
        .disabled = 1,
        .exclude_kernel = 0,
	.exclude_user = 0,
        .exclude_hv = 1,
};

struct perf_event_attr attr_instrs1 = {
        .type = PERF_TYPE_RAW,
	// DTLB_LOAD_MISSES.WALK_COMPLETED_2M_4M
        .config = (0x04 << 8) | 0x49,
        .size = sizeof(struct perf_event_attr),
        .disabled = 1,
        .exclude_kernel = 0,
	.exclude_user = 0,
        .exclude_hv = 1,
};

/*
 * 't->pid' should be the pointer to the relevant 'struct pid' having reference
 * count.  Caller must put the returned task, unless it is NULL.
 */
static inline struct task_struct *damon_get_task_struct(struct damon_target *t)
{
	return get_pid_task(t->pid, PIDTYPE_PID);
}

static inline bool damon_get_task_structs(struct damon_target *t) {
	
	struct task_struct *subtask;

	if (t->nr_profile_thread > 0) {
		pr_warn("task_structs not freed\n");
		return false;
	}

	read_lock(&tasklist_lock);

	t->profile[0] = get_pid_task(t->pid, PIDTYPE_PID);

	if (!t->profile) {
		pr_warn("get_pid_task failed.\n");
		return false;
	}

	++t->nr_profile_thread;

	for_each_thread(t->profile[0], subtask) {
		t->profile[t->nr_profile_thread] = subtask;
		++t->nr_profile_thread;

		if (t->nr_profile_thread == MAX_PROFILE_THREAD)
			break;
	}
	read_unlock(&tasklist_lock);

	return true;
}

static inline void damon_put_task_structs(struct damon_target *t) {
	
	int i;

	if (t->profile[0]) {
		put_task_struct(t->profile[0]);
	}

	for (i = 0; i < MAX_PROFILE_THREAD; ++i)
		t->profile[i] = NULL;

	t->nr_profile_thread = 0;

}

/*
 * Get the mm_struct of the given target
 *
 * Caller _must_ put the mm_struct after use, unless it is NULL.
 *
 * Returns the mm_struct of the target on success, NULL on failure
 */
static struct mm_struct *damon_get_mm(struct damon_target *t)
{
	struct task_struct *task;
	struct mm_struct *mm;

	task = damon_get_task_struct(t);
	if (!task)
		return NULL;

	mm = get_task_mm(task);
	put_task_struct(task);
	return mm;
}

/*
 * Functions for the initial monitoring target regions construction
 */

/*
 * Size-evenly split a region into 'nr_pieces' small regions
 *
 * Returns 0 on success, or negative error code otherwise.
 */
static int damon_va_evenly_split_region(struct damon_target *t,
		struct damon_region *r, unsigned int nr_pieces)
{
	unsigned long sz_orig, sz_piece, orig_end;
	struct damon_region *n = NULL, *next;
	unsigned long start;

	if (!r || !nr_pieces)
		return -EINVAL;

	orig_end = r->ar.end;
	sz_orig = damon_sz_region(r);
	sz_piece = ALIGN_DOWN(sz_orig / nr_pieces, DAMON_MIN_REGION);

	if (!sz_piece)
		return -EINVAL;

	r->ar.end = r->ar.start + sz_piece;
	next = damon_next_region(r);
	for (start = r->ar.end; start + sz_piece <= orig_end;
			start += sz_piece) {
		n = damon_new_region(start, start + sz_piece);
		// Update the # of thps in this region (ZS)
		damon_update_region_thp(n, t);
		if (!n)
			return -ENOMEM;
		damon_insert_region(n, r, next, t);
		r = n;
	}
	/* complement last region for possible rounding error */
	if (n)
		n->ar.end = orig_end;

	return 0;
}

static unsigned long sz_range(struct damon_addr_range *r)
{
	return r->end - r->start;
}

/*
 * Find three regions separated by two biggest unmapped regions
 *
 * vma		the head vma of the target address space
 * regions	an array of three address ranges that results will be saved
 *
 * This function receives an address space and finds three regions in it which
 * separated by the two biggest unmapped regions in the space.  Please refer to
 * below comments of '__damon_va_init_regions()' function to know why this is
 * necessary.
 *
 * Returns 0 if success, or negative error code otherwise.
 */
static int __damon_va_three_regions(struct mm_struct *mm,
				       struct damon_addr_range regions[3])
{
	struct damon_addr_range first_gap = {0}, second_gap = {0};
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *vma, *prev = NULL;
	unsigned long start;

	/*
	 * Find the two biggest gaps so that first_gap > second_gap > others.
	 * If this is too slow, it can be optimised to examine the maple
	 * tree gaps.
	 */
	for_each_vma(vmi, vma) {
		unsigned long gap;

		if (!prev) {
			start = vma->vm_start;
			goto next;
		}
		gap = vma->vm_start - prev->vm_end;

		if (gap > sz_range(&first_gap)) {
			second_gap = first_gap;
			first_gap.start = prev->vm_end;
			first_gap.end = vma->vm_start;
		} else if (gap > sz_range(&second_gap)) {
			second_gap.start = prev->vm_end;
			second_gap.end = vma->vm_start;
		}
next:
		prev = vma;
	}

	if (!sz_range(&second_gap) || !sz_range(&first_gap))
		return -EINVAL;

	/* Sort the two biggest gaps by address */
	if (first_gap.start > second_gap.start)
		swap(first_gap, second_gap);

	/* Store the result */
	regions[0].start = ALIGN(start, DAMON_MIN_REGION);
	regions[0].end = ALIGN(first_gap.start, DAMON_MIN_REGION);
	regions[1].start = ALIGN(first_gap.end, DAMON_MIN_REGION);
	regions[1].end = ALIGN(second_gap.start, DAMON_MIN_REGION);
	regions[2].start = ALIGN(second_gap.end, DAMON_MIN_REGION);
	regions[2].end = ALIGN(prev->vm_end, DAMON_MIN_REGION);

	return 0;
}

/*
 * Get the three regions in the given target (task)
 *
 * Returns 0 on success, negative error code otherwise.
 */
static int damon_va_three_regions(struct damon_target *t,
				struct damon_addr_range regions[3])
{
	struct mm_struct *mm;
	int rc;

	mm = damon_get_mm(t);
	if (!mm)
		return -EINVAL;

	mmap_read_lock(mm);
	rc = __damon_va_three_regions(mm, regions);
	mmap_read_unlock(mm);

	mmput(mm);
	return rc;
}

/*
 * Initialize the monitoring target regions for the given target (task)
 *
 * t	the given target
 *
 * Because only a number of small portions of the entire address space
 * is actually mapped to the memory and accessed, monitoring the unmapped
 * regions is wasteful.  That said, because we can deal with small noises,
 * tracking every mapping is not strictly required but could even incur a high
 * overhead if the mapping frequently changes or the number of mappings is
 * high.  The adaptive regions adjustment mechanism will further help to deal
 * with the noise by simply identifying the unmapped areas as a region that
 * has no access.  Moreover, applying the real mappings that would have many
 * unmapped areas inside will make the adaptive mechanism quite complex.  That
 * said, too huge unmapped areas inside the monitoring target should be removed
 * to not take the time for the adaptive mechanism.
 *
 * For the reason, we convert the complex mappings to three distinct regions
 * that cover every mapped area of the address space.  Also the two gaps
 * between the three regions are the two biggest unmapped areas in the given
 * address space.  In detail, this function first identifies the start and the
 * end of the mappings and the two biggest unmapped areas of the address space.
 * Then, it constructs the three regions as below:
 *
 *     [mappings[0]->start, big_two_unmapped_areas[0]->start)
 *     [big_two_unmapped_areas[0]->end, big_two_unmapped_areas[1]->start)
 *     [big_two_unmapped_areas[1]->end, mappings[nr_mappings - 1]->end)
 *
 * As usual memory map of processes is as below, the gap between the heap and
 * the uppermost mmap()-ed region, and the gap between the lowermost mmap()-ed
 * region and the stack will be two biggest unmapped regions.  Because these
 * gaps are exceptionally huge areas in usual address space, excluding these
 * two biggest unmapped regions will be sufficient to make a trade-off.
 *
 *   <heap>
 *   <BIG UNMAPPED REGION 1>
 *   <uppermost mmap()-ed region>
 *   (other mmap()-ed regions and small unmapped regions)
 *   <lowermost mmap()-ed region>
 *   <BIG UNMAPPED REGION 2>
 *   <stack>
 */
static void __damon_va_init_regions(struct damon_ctx *ctx,
				     struct damon_target *t)
{
	struct damon_target *ti;
	struct damon_region *r;
	struct damon_addr_range regions[3];
	unsigned long sz = 0, nr_pieces;
	int i, tidx = 0;

	if (damon_va_three_regions(t, regions)) {
		damon_for_each_target(ti, ctx) {
			if (ti == t)
				break;
			tidx++;
		}
		pr_debug("Failed to get three regions of %dth target\n", tidx);
		return;
	}

	for (i = 0; i < 3; i++)
		sz += regions[i].end - regions[i].start;
	if (ctx->attrs.min_nr_regions)
		sz /= ctx->attrs.min_nr_regions;
	if (sz < DAMON_MIN_REGION)
		sz = DAMON_MIN_REGION;

	/* Set the initial three regions of the target */
	for (i = 0; i < 3; i++) {
		r = damon_new_region(regions[i].start, regions[i].end);
		// Update the # of thps in this region (ZS)
		damon_update_region_thp(r, t);
		if (!r) {
			pr_err("%d'th init region creation failed\n", i);
			return;
		}
		damon_add_region(r, t);

		nr_pieces = (regions[i].end - regions[i].start) / sz;
		damon_va_evenly_split_region(t, r, nr_pieces);
	}
}

/* Initialize '->regions_list' of every target (task) */
static void damon_va_init(struct damon_ctx *ctx)
{
	struct damon_target *t;

	damon_for_each_target(t, ctx) {
		/* the user may set the target regions as they want */
		if (!damon_nr_regions(t))
			__damon_va_init_regions(ctx, t);
	}
}

/*
 * Update regions for current memory mappings
 */
static void damon_va_update(struct damon_ctx *ctx)
{
	struct damon_addr_range three_regions[3];
	struct damon_target *t;

	damon_for_each_target(t, ctx) {
		if (damon_va_three_regions(t, three_regions))
			continue;
		damon_set_regions(t, three_regions, 3);
	}
}

static int damon_mkold_pmd_entry(pmd_t *pmd, unsigned long addr,
		unsigned long next, struct mm_walk *walk)
{
	//	pte_t *pte;
	spinlock_t *ptl;

	if (pmd_trans_huge(*pmd)) {
		ptl = pmd_lock(walk->mm, pmd);
		if (!pmd_present(*pmd)) {
			spin_unlock(ptl);
			return 0;
		}

		if (pmd_trans_huge(*pmd)) {
			damon_pmdp_mkold(pmd, walk->vma, addr);
			spin_unlock(ptl);
			return 0;
		}
		spin_unlock(ptl);
	}

	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return 0;
	ptl = pmd_lock(walk->mm, pmd);
	if (!pmd_present(*pmd)) {
		goto out;
	}
	damon_nonleaf_pmdp_mkold(pmd, walk->vma, addr);
out:
	spin_unlock(ptl);
	return 0;
}

#ifdef CONFIG_HUGETLB_PAGE
static void damon_hugetlb_mkold(pte_t *pte, struct mm_struct *mm,
				struct vm_area_struct *vma, unsigned long addr)
{
	bool referenced = false;
	pte_t entry = huge_ptep_get(pte);
	struct page *page = pte_page(entry);

	get_page(page);

	if (pte_young(entry)) {
		referenced = true;
		entry = pte_mkold(entry);
		set_huge_pte_at(mm, addr, pte, entry);
	}

#ifdef CONFIG_MMU_NOTIFIER
	if (mmu_notifier_clear_young(mm, addr,
				     addr + huge_page_size(hstate_vma(vma))))
		referenced = true;
#endif /* CONFIG_MMU_NOTIFIER */

	if (referenced)
		set_page_young(page);

	set_page_idle(page);
	put_page(page);
}

static int damon_mkold_hugetlb_entry(pte_t *pte, unsigned long hmask,
				     unsigned long addr, unsigned long end,
				     struct mm_walk *walk)
{
	struct hstate *h = hstate_vma(walk->vma);
	spinlock_t *ptl;
	pte_t entry;

	ptl = huge_pte_lock(h, walk->mm, pte);
	entry = huge_ptep_get(pte);
	if (!pte_present(entry))
		goto out;

	damon_hugetlb_mkold(pte, walk->mm, walk->vma, addr);

out:
	spin_unlock(ptl);
	return 0;
}
#else
#define damon_mkold_hugetlb_entry NULL
#endif /* CONFIG_HUGETLB_PAGE */

static const struct mm_walk_ops damon_mkold_ops = {
	.pmd_entry = damon_mkold_pmd_entry,
	.hugetlb_entry = damon_mkold_hugetlb_entry,
};

static void damon_va_mkold(struct mm_struct *mm, unsigned long addr)
{
	mmap_read_lock(mm);
	walk_page_range(mm, addr, addr + 1, &damon_mkold_ops, NULL);
	mmap_read_unlock(mm);
}

/*
 * Functions for the access checking of the regions
 */

static void __damon_va_prepare_access_check(struct mm_struct *mm,
					struct damon_region *r)
{
	r->sampling_addr = damon_rand(r->ar.start, r->ar.end);

	damon_va_mkold(mm, r->sampling_addr);
}

static void damon_va_prepare_access_checks(struct damon_ctx *ctx)
{
	struct damon_target *t;
	struct mm_struct *mm;
	struct damon_region *r;

	damon_for_each_target(t, ctx) {
		mm = damon_get_mm(t);
		if (!mm)
			continue;
		damon_for_each_region(r, t)
			__damon_va_prepare_access_check(mm, r);
		mmput(mm);
	}
}

struct damon_young_walk_private {
	unsigned long *page_sz;
	bool young;
};

static int damon_young_pmd_entry(pmd_t *pmd, unsigned long addr,
		unsigned long next, struct mm_walk *walk)
{
	//	pte_t *pte;
	spinlock_t *ptl;
	struct page *page;
	struct damon_young_walk_private *priv = walk->private;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (pmd_trans_huge(*pmd)) {
		ptl = pmd_lock(walk->mm, pmd);
		if (!pmd_present(*pmd)) {
			spin_unlock(ptl);
			return 0;
		}

		if (!pmd_trans_huge(*pmd)) {
			spin_unlock(ptl);
			goto regular_page;
		}
		page = damon_get_page(pmd_pfn(*pmd));
		if (!page)
			goto huge_out;
		if (pmd_young(*pmd) || !page_is_idle(page) ||
					mmu_notifier_test_young(walk->mm,
						addr)) {
			*priv->page_sz = HPAGE_PMD_SIZE;
			priv->young = true;
		}
		put_page(page);
huge_out:
		spin_unlock(ptl);
		return 0;
	}

regular_page:
#endif	/* CONFIG_TRANSPARENT_HUGEPAGE */
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return -EINVAL;

	ptl = pmd_lock(walk->mm, pmd);
	if (!pmd_present(*pmd)) {
		goto out;
	}

	if (pmd_young(*pmd) ||
		mmu_notifier_test_young(walk->mm, addr)) {
		*priv->page_sz = HPAGE_PMD_SIZE;
		priv->young = true;
	}

out:
	spin_unlock(ptl);
	return 0;
}

#ifdef CONFIG_HUGETLB_PAGE
static int damon_young_hugetlb_entry(pte_t *pte, unsigned long hmask,
				     unsigned long addr, unsigned long end,
				     struct mm_walk *walk)
{
	struct damon_young_walk_private *priv = walk->private;
	struct hstate *h = hstate_vma(walk->vma);
	struct page *page;
	spinlock_t *ptl;
	pte_t entry;

	ptl = huge_pte_lock(h, walk->mm, pte);
	entry = huge_ptep_get(pte);
	if (!pte_present(entry))
		goto out;

	page = pte_page(entry);
	get_page(page);

	if (pte_young(entry) || !page_is_idle(page) ||
	    mmu_notifier_test_young(walk->mm, addr)) {
		*priv->page_sz = huge_page_size(h);
		priv->young = true;
	}

	put_page(page);

out:
	spin_unlock(ptl);
	return 0;
}
#else
#define damon_young_hugetlb_entry NULL
#endif /* CONFIG_HUGETLB_PAGE */

static const struct mm_walk_ops damon_young_ops = {
	.pmd_entry = damon_young_pmd_entry,
	.hugetlb_entry = damon_young_hugetlb_entry,
};

static bool damon_va_young(struct mm_struct *mm, unsigned long addr,
		unsigned long *page_sz)
{
	struct damon_young_walk_private arg = {
		.page_sz = page_sz,
		.young = false,
	};

	mmap_read_lock(mm);
	walk_page_range(mm, addr, addr + 1, &damon_young_ops, &arg);
	mmap_read_unlock(mm);
	return arg.young;
}

/*
 * Check whether the region was accessed after the last preparation
 *
 * mm	'mm_struct' for the given virtual address space
 * r	the region to be checked
 */
static void __damon_va_check_access(struct mm_struct *mm,
				struct damon_region *r, bool same_target)
{
	static unsigned long last_addr;
	static unsigned long last_page_sz = HPAGE_PMD_SIZE;
	static bool last_accessed;

	/* If the region is in the last checked page, reuse the result */
	if (same_target && (ALIGN_DOWN(last_addr, last_page_sz) ==
				ALIGN_DOWN(r->sampling_addr, last_page_sz))) {
		if (last_accessed)
			r->nr_accesses++;
		return;
	}

	last_accessed = damon_va_young(mm, r->sampling_addr, &last_page_sz);
	if (last_accessed)
		r->nr_accesses++;

	last_addr = r->sampling_addr;
}

static unsigned int damon_va_check_accesses(struct damon_ctx *ctx)
{
	struct damon_target *t;
	struct mm_struct *mm;
	struct damon_region *r;
	unsigned int max_nr_accesses = 0;
	bool same_target;

	damon_for_each_target(t, ctx) {
		mm = damon_get_mm(t);
		if (!mm)
			continue;
		same_target = false;
		damon_for_each_region(r, t) {
			__damon_va_check_access(mm, r, same_target);
			max_nr_accesses = max(r->nr_accesses, max_nr_accesses);
			same_target = true;
		}
		mmput(mm);
	}

	return max_nr_accesses;
}

/*
 * Functions for the target validity check and cleanup
 */

static bool damon_va_target_valid(struct damon_target *t)
{
	struct task_struct *task;

	task = damon_get_task_struct(t);
	if (task) {
		put_task_struct(task);
		return true;
	}

	return false;
}

// Write all pmd-aligned gfns into ivshmem with the range of [start, end) (ZS)
struct tlbh_write_gfn_ctx{
	unsigned long *ivshmem_base;
	int is_promote;
};

static int tlbh_write_gfns(pmd_t *pmd, unsigned long addr,
		unsigned long next, struct mm_walk *walk) {
	
	unsigned long *buffer_base = ((struct tlbh_write_gfn_ctx*)(walk->private))->ivshmem_base;
	int is_promote = ((struct tlbh_write_gfn_ctx*)(walk->private))->is_promote;
	unsigned long *addr_num;
	unsigned long pfn, buffer_idx;

	pte_t *pte;
	spinlock_t *ptl;

	if (pmd_none(*pmd) || pmd_devmap(*pmd)) {
		// PMD is devmap or not present, continue
		return 0;
	}

	if (is_promote) {
		addr_num = &buffer_base[1];
		buffer_idx = PROMOTE_START + *(addr_num);
	} else {
		addr_num = &buffer_base[0];
		buffer_idx = DEMOTE_START + *(addr_num);
	}

	if (pmd_trans_huge(*pmd)) {
		if (likely(addr_num &&
			((*addr_num) <= MAX_ELEM_AMOUNT))) {

			ptl = pmd_lock(walk->mm, pmd);
			if (!pmd_present(*pmd)) {
				spin_unlock(ptl);
				return 0;
			}

			if (pmd_trans_huge(*pmd)) {
				pfn = pmd_pfn(*pmd);
				if (likely(pfn)) {
					buffer_base[buffer_idx] = pfn;
					++(*addr_num);
					spin_unlock(ptl);
					return 0;
				}
			}
			spin_unlock(ptl);
		}
	}

	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return 0;

	if (likely(addr_num &&
		((*addr_num) <= MAX_ELEM_AMOUNT))) {

		pte = pte_offset_map_lock(walk->mm, pmd, addr, &ptl);
		if (!pte_present(*pte)) {
			pte_unmap_unlock(pte, ptl);
			return 0;
		}
		// pfn = pte_pfn(*pte);
		// Get the pfn of the pte page (ZS)
		pfn = (virt_to_phys(pte) >> PAGE_SHIFT);
		if (likely(pfn)) {
			buffer_base[buffer_idx] = pfn;
			++(*addr_num);
		}
		
		pte_unmap_unlock(pte, ptl);
	}

	return 0;

}

static const struct mm_walk_ops tlbh_write_gfns_ops = {
	.pmd_entry = tlbh_write_gfns,
};

static void tlbh_write_gfns_range(struct mm_struct *mm,
		unsigned long start, unsigned long end,
		unsigned long *tlbh_ivshmem_base, int is_promote) {

	struct tlbh_write_gfn_ctx private;

	if (!tlbh_ivshmem_base) {
		pr_warn("damos_tlbh: Skipping writes to ivshmem due no base address not available.\n");
		return;
	}

	private.ivshmem_base = tlbh_ivshmem_base;
        private.is_promote = is_promote;

	mmap_read_lock(mm);
	walk_page_range(mm, start, end, &tlbh_write_gfns_ops, &private);
	mmap_read_unlock(mm);
	
}

//	// Demote all THPs within the range [start, end) using mm_walk (ZS)
//	static int tlbh_demote_huge_pmd(pmd_t *pmd, unsigned long addr,
//			unsigned long next, struct mm_walk *walk) {
//		
//		struct page *page = NULL;
//		unsigned long *err_cnt = walk->private;
//	
//		if (pmd_trans_huge(*pmd)) {
//			pmd_t demote_pmd;
//			spinlock_t *ptl = pmd_trans_huge_lock(pmd, walk->vma);
//			if (!ptl) {
//				++err_cnt;
//				return 0;
//			}
//	
//			demote_pmd = *pmd;
//	
//			if (unlikely(!pmd_present(demote_pmd))) {
//				VM_BUG_ON(thp_migration_supported() &&
//						!is_pmd_migration_entry(demote_pmd));
//				goto err_pmd_unlock;
//			}
//	
//			page = pmd_page(demote_pmd);
//	
//			// Do not demote non-anonymous huge pages
//			if (!PageAnon(page)) {
//				goto err_pmd_unlock;
//			}
//	
//			get_page(page);
//			spin_unlock(ptl);
//			lock_page(page);
//			if (unlikely(split_huge_page(page))) {
//				++err_cnt;
//			}
//			unlock_page(page);
//			put_page(page);
//			return 0;
//	
//	err_pmd_unlock:
//			spin_unlock(ptl);
//			++err_cnt;
//		}
//	
//		return 0;
//	}
//	
//	static const struct mm_walk_ops tlbh_demote_region_ops = {
//		.pmd_entry = tlbh_demote_huge_pmd,
//	};
//	
//	static unsigned long damo_tlbh_demote_memory_region(struct mm_struct *mm,
//			unsigned long start, unsigned long end)
//	{
//		unsigned long err_cnt = 0;
//	
//		mmap_read_lock(mm);	
//		walk_page_range(mm, start, end, &tlbh_demote_region_ops, &err_cnt);
//		mmap_read_unlock(mm);
//	
//		return err_cnt;
//	}

//	static uintptr_t find_page_table_page(struct mm_struct *mm, unsigned long vaddr) {
//		//	pgd_t *pgd = pgd_offset(mm, vaddr);
//		struct page *pte_page = NULL;
//		pte_t *pte = NULL;
//	
//		//	if (pgd_none(*pgd) || pgd_bad(*pgd))
//		//		return;
//		//	
//		//	pud_t *pud = pud_offset(pgd, vaddr);
//		//	if (pud_none(*pud) || pud_bad(*pud))
//		//		return;
//		
//		//	pmd_t *pmd = pmd_offset(pud, vaddr);
//		pmd_t *pmd = pmd_off(mm, vaddr);
//		if (pmd_none(*pmd) || pmd_bad(*pmd))
//			return 0;
//		
//		if (pmd_huge(*pmd)) {
//		    // It's a huge page, mapped at PMD level
//		    //	pr_warn("Mapped at PMD level: PMD phys page = %llx\n",
//		    //	       (unsigned long long)pmd_pfn(*pmd) << PAGE_SHIFT);
//		    return (uintptr_t) pfn_to_page(pmd_pfn(*pmd));
//		}
//		
//		pte = pte_offset_kernel(pmd, vaddr);
//		if (pte_none(*pte))
//			return 0;
//		
//		pte_page = virt_to_page(pte);
//		//	pr_warn("PTE page: %p\n", pte_page);
//		return (uintptr_t) pte_page;
//	}

//	No need to collapse guest's page table pages in guest
//	address space (ZS)

//	#ifdef CONFIG_X86
//	#include <asm/pgalloc.h>

//	static inline void paravirt_alloc_pte(struct mm_struct *mm, unsigned long pfn) {
//		PVOP_VCALL2((paravirt_ops.mmu).alloc_pte, mm, pfn);
//	}
//	
//	static inline void pmd_populate_kernel(struct mm_struct *mm,
//					       pmd_t *pmd, pte_t *pte) {
//		paravirt_alloc_pte(mm, __pa(pte) >> PAGE_SHIFT);
//		set_pmd(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
//	}

//	static int collapse_pte_pages(struct mm_struct *mm, unsigned long start_addr,
//			unsigned long end_addr) {
//		struct page *huge_page;
//		pmd_t *pmd_now = NULL, *pmd_prev = NULL;
//		pte_t *prev_pte = NULL;
//		// pgtable_t new_pt;
//		int i = 0;
//		unsigned long addr = start_addr;
//		
//		// Allocate a 2MB hugepage for merging
//		huge_page = alloc_pages(GFP_KERNEL | __GFP_COMP | __GFP_ZERO,
//				HPAGE_PMD_ORDER);
//		if (!huge_page)
//			return -ENOMEM;
//		
//		// Lock page table
//		down_write(&mm->mmap_lock);
//		
//		for (; start_addr < end_addr; addr += HPAGE_PMD_SIZE) {
//			struct vm_area_struct *flush_vma = find_vma(mm, addr);
//			if (!flush_vma)
//				continue;
//	
//			pmd_now = pmd_offset(pud_offset(p4d_offset(pgd_offset(mm, addr), addr), addr), addr);
//	
//			if (pmd_now == pmd_prev)
//				continue;
//			
//			if (pmd_none(*pmd_now) || !pmd_present(*pmd_now)
//					|| pmd_trans_huge(*pmd_now)) {
//				// skip invalid entries
//				continue;
//			}
//			
//			pte_t *old_pte = pte_offset_kernel(pmd_now, addr);
//			pte_t *old_pte_base = (pte_t *)((unsigned long)old_pte & PAGE_MASK);
//			if (prev_pte == old_pte_base)
//				continue;
//			struct page *old_pte_page = virt_to_page(old_pte_base);
//			
//			// Offset into huge page
//			void *dst = page_address(huge_page) + (i * PAGE_SIZE);
//			void *src = (void *)old_pte_base;
//			
//			// Copy page table content
//			memcpy(dst, src, PAGE_SIZE);
//			
//			pmd_clear(pmd_now);
//	
//			struct page *pte_pg = virt_to_page(old_pte_base);
//			pr_warn("Freeing PTE page at %px (struct page: %p, mapcount: %d)\n",
//					        old_pte_base, pte_pg, page_mapcount(pte_pg));
//	
//			pte_free_kernel(mm, old_pte_base);
//			// Replace PTE page pointer with new one
//			// new_pt = virt_to_page(dst); // convert back to struct page*
//			pmd_populate_kernel(mm, pmd_now, (pte_t *)dst);
//			
//			// Flush TLB to avoid stale entries
//			flush_tlb_page(flush_vma, addr);
//	
//			// Free up the old base page table pages
//			if (page_mapcount(old_pte_page) > -1) {
//				pr_warn("Old PTE page at 0x%lx still mapped\n", addr);
//			}
//	
//			if (i >= 511)
//				i = 0;
//			else
//				++i;
//	
//			pmd_prev = pmd_now;
//			prev_pte = old_pte_base;
//		}
//		
//		up_write(&mm->mmap_lock);
//		return 0;
//	}

//	static int collapse_pte_pages(struct mm_struct *mm, unsigned long start_addr,
//			unsigned long end_addr) {
//	
//		return 0;
//	}
//	
//	#else
//	
//	static inline int collapse_pte_pages(struct mm_struct *mm, unsigned long start_addr,
//			unsigned long end_addr) {}
//	
//	#endif
//	
//	// Print page table page address of a range [start,end) (ZS)
//	static void hotgpt_promote_pgtable_page(struct mm_struct *mm,
//			unsigned long start, unsigned long end)
//	{
//		//	unsigned long i;
//		//	uintptr_t prev_addr = 0;
//		//	uintptr_t now_addr = 0;
//	
//		collapse_pte_pages(mm, start, end);
//	
//	}

#ifndef CONFIG_ADVISE_SYSCALLS
static unsigned long damos_madvise(struct damon_target *target,
		struct damon_region *r, int behavior)
{
	return 0;
}

static unsigned long do_damos_tlbh(struct damon_target *target,
		struct damon_region *r, struct damos_quota *quota)
{
	return 0;
}
static void damon_check_intention_promote(struct damon_ctx *context) {}

#else
static unsigned long damos_madvise(struct damon_target *target,
		struct damon_region *r, int behavior)
{
	struct mm_struct *mm;
	unsigned long start = PAGE_ALIGN(r->ar.start);
	unsigned long len = PAGE_ALIGN(damon_sz_region(r));
	unsigned long applied;

	mm = damon_get_mm(target);
	if (!mm)
		return 0;

	applied = do_madvise(mm, start, len, behavior) ? 0 : len;
	mmput(mm);

	return applied;
}

static inline unsigned long _nr_2MB_regions(unsigned long start,
		unsigned long end) {
	
	return end > start ? ((end - start) / HPAGE_PMD_SIZE) : 0;

}

// do_damos_tlbh: Apply MADV_HUGEPAGE and MADV_NOHUGEPAGE
// respectively to corresponding promote and demote regions
static unsigned long do_damos_tlbh(struct damon_target *target,
		struct damon_region *r, struct damos_quota *quota)
{
	unsigned long pmd_aligned_len = damon_tlbh_effective_sz_region(r);
	unsigned long pmd_aligned_start = ALIGN(r->ar.start, HPAGE_PMD_SIZE);
	
	unsigned long applied;

	unsigned long nr_2MB_regions = _nr_2MB_regions(pmd_aligned_start, pmd_aligned_start + pmd_aligned_len);
	unsigned long quota_esz = 0UL;

	unsigned long this_region_area, this_region_trail_area;

	if (target->is_promote && pmd_aligned_len <= 0)
		return 0;

	if (quota)
		quota_esz = quota->esz;

	if (target->is_promote == true) {
		// Conditionally call MADV_COLLAPSE or MADV_HUGEPAGE
		// depending on if the region is all backed by huge
		// pages.
		++r->tlbh_freq_hot;
		// The region has been marked hot for MAX_TLBH_HOT_FREQ times.
		// Put it into the intention promote queue. (ZS)
		if (r->tlbh_freq_hot >= MAX_TLBH_HOT_FREQ) {
			// Only insert when allowed 
			// and regions to demote has 
			// not exceeded the quota. (ZS)
			if ((target->allow_intention_insert == true) && 
				(r->nr_thps < nr_2MB_regions) &&
				((target->cumulated_2MB_regions +
				 nr_2MB_regions) << 21 <= quota_esz)) {

				// r->tlbh_freq_hot = 0;
				r->tlbh_freq_hot = MAX_TLBH_HOT_FREQ;

				list_add_tail(&r->intention_promote_node,
						&target->intention_promote);
				++target->nr_intention_promote_regions;
				//	target->cumulated_2MB_regions += nr_2MB_regions;
				//	target->cumulated_trail_2MB_regions +=
				//		div64_ul(nr_2MB_regions, 10);
				//	this_region_area = nr_2MB_regions - r->nr_thps;
				this_region_area = nr_2MB_regions;
				// Use fixed 10% of nr_2MB_regions instead (ZS)
				this_region_trail_area = div64_ul(nr_2MB_regions, 10);
				if (this_region_trail_area > this_region_area)
					this_region_trail_area = this_region_area;
				target->cumulated_2MB_regions += this_region_area;
				target->cumulated_trail_2MB_regions +=
					// div64_ul((nr_2MB_regions - r->nr_thps), 10);
					this_region_trail_area;

			} else {
				// If not allowed to insert due to ongoing
				// performance profiling,
				// set the region with MAX_TLBH_HOT_FREQ. (ZS)
				r->tlbh_freq_hot = MAX_TLBH_HOT_FREQ;
			}
		}

		applied = 0;

	} else {

		// Deduct tlbh_freq_hot by 1 if a region previously marked hot
		// is not marked hot again in this sampling period (ZS)
		if (r->tlbh_freq_hot > 0) {
			--r->tlbh_freq_hot;
		}

		applied = 0;

	}


	return applied;
}

/*
 * IPC/CPI
 */
static inline bool check_perf_improve(u64 cycle1, u64 instr1,
		u64 cycle2, u64 instr2) {

	u64 cpi1, cpi2, ipc1, ipc2;

	if (cycle1 == 0) {
		pr_warn("profiling: cycle1 is 0.\n");
		return false;
	}

	if (cycle2 == 0) {
		pr_warn("profiling: cycle2 is 0.\n");
		return false;
	}

	if (instr1 == 0 && instr2 > 0)
		return true;
	
	if (instr2 == 0)
		return false;

	cpi1 = div64_u64(cycle1, instr1);
	cpi2 = div64_u64(cycle2, instr2);

	ipc1 = div64_u64(instr1, cycle1);
	ipc2 = div64_u64(instr2, cycle2);

	if (ipc2 >= 1 && ipc1 < 1) {
		pr_warn("cpi1:%llu, ipc1:%llu, cpi2:%llu, ipc2:%llu\n",
				cpi1, ipc1, cpi2, ipc2);

		return true;
	} else if (ipc2 < 1 && ipc1 >= 1) {
		return false;
	} else if (ipc2 < 1 && ipc1 < 1) {
		if (cpi2 < cpi1) {
			pr_warn("cpi1:%llu, cpi2:%llu",
					cpi1, cpi2);
			return true;
		}
		return cpi2 < cpi1;
	} else {
		if (ipc2 > ipc1) {
			pr_warn("ipc1:%llu, ipc2:%llu",
					ipc1, ipc2);
			return true;
		}
		return ipc2 > ipc1;
	}
}

/*
 * TLB Miss
 */
//	static inline bool check_perf_improve(u64 tlbldmiss1, u64 tlbstmiss1,
//			u64 tlbldmiss2, u64 tlbstmiss2) {
//	
//		u64 total_tlbmiss1 = tlbldmiss1 + tlbstmiss1;
//		u64 total_tlbmiss2 = tlbldmiss2 + tlbstmiss2;
//	
//		if (total_tlbmiss2 < total_tlbmiss1) {
//			pr_warn("total_tlbmiss1:%llu, total_tlbmiss2:%llu\n",
//					total_tlbmiss1, total_tlbmiss2);
//			return true;
//		} else {
//			return false;
//		}
//	
//	}

/*
 * Page walk latency
 */
//	static inline bool check_perf_improve(u64 pending1, u64 complete1,
//			u64 pending2, u64 complete2) {
//	
//		u64 lat1, lat2, revlat1, revlat2;
//	
//		if (pending1 == 0) {
//			pr_warn("profiling: pending1 is 0.\n");
//			return false;
//		}
//	
//		if (pending2 == 0) {
//			pr_warn("profiling: pending2 is 0.\n");
//			return false;
//		}
//	
//		if (complete2 == 0 && complete1 > 0)
//			return true;
//		
//		if (complete1 == 0)
//			return false;
//	
//		lat1 = div64_u64(pending1, complete1);
//		lat2 = div64_u64(pending2, complete2);
//	
//		revlat1 = div64_u64(complete1, pending1);
//		revlat2 = div64_u64(complete2, pending2);
//	
//		if (lat1 >= 1 && lat2 < 1) {
//			pr_warn("lat1:%llu, revlat1:%llu, lat2:%llu, revlat2:%llu\n",
//					lat1, revlat1, lat2, revlat2);
//	
//			return true;
//		} else if (lat1 < 1 && lat2 >= 1) {
//			return false;
//		} else if (lat1 < 1 && lat2 < 1) {
//			if (revlat2 > revlat1) {
//				pr_warn("revlat1:%llu, revlat2:%llu",
//						revlat1, revlat2);
//				return true;
//			}
//			return revlat2 < revlat1;
//		} else {
//			if (lat2 < lat1) {
//				pr_warn("lat1:%llu, lat2:%llu",
//						lat1, lat2);
//				return true;
//			}
//			return lat2 < lat1;
//		}
//	}

static void do_hugepage_reallocate(struct damon_ctx *ctx, struct damon_target *t,
		struct damos *s, struct damos_quota *quota, bool trail_flag) {

	//	unsigned int demote_score = quota->min_score;
	unsigned int demote_score = 0;
	unsigned long pmd_aligned_start, pmd_aligned_len;
	unsigned long cumulated_promote_sz;
	unsigned long trail_sz = (t->cumulated_trail_2MB_regions) << 21;
	unsigned long remaining_sz = (t->cumulated_2MB_regions -
			t->cumulated_trail_2MB_regions) << 21;

	unsigned int i = 0;
	struct damon_region *r, *next_r;

	struct mm_struct *mm = NULL;

	mm = damon_get_mm(t);
	if (!mm)
		return;

	if (trail_flag) {
		cumulated_promote_sz = trail_sz;
	} else {
		cumulated_promote_sz = remaining_sz;
	}

	// Setting up the ivshmem device for damos_tlbh (ZS)
	t->tlbh_ivshmem_base = (unsigned long*)memremap(TLBH_IVSHMEM_ADDR,
			SHM_SIZE, MEMREMAP_WB);
	if (!t->tlbh_ivshmem_base) {
                pr_warn("damos_tlbh: memremap of ivshmem device returns %ld.\n",
                                PTR_ERR(t->tlbh_ivshmem_base));
        } else {
                // Initialize num of 2MB regions to demote
                // and promote respectively
                (t->tlbh_ivshmem_base)[0] = 0UL; // Demote region count
                (t->tlbh_ivshmem_base)[1] = 0UL; // Promote region count
        }

	// Demote the memory regions until there's enough
	// huge page quota to promote num_promote_regions
	// of memory regions in the intention promote
	// queue (ZS)
	while (quota->charged_sz + cumulated_promote_sz
	                > quota->esz) {
	       // Demote from the region with lowest
	       // scheme score, all the way up
	       damon_for_each_region_safe(r, next_r, t) {
		       if (r->nr_thps > 0 &&
				//	damon_tlbh_score(ctx, r, s) == demote_score) {
				r->tlbh_freq_hot == demote_score) {

				unsigned long remaining_demote_sz = cumulated_promote_sz -
					(quota->esz - quota->charged_sz);

				pmd_aligned_start = ALIGN(r->ar.start, HPAGE_PMD_SIZE);
				pmd_aligned_len = damon_tlbh_effective_sz_region(r);

				if ( ((r->nr_thps) << 21) < pmd_aligned_len) {
					//	pmd_aligned_start = pmd_aligned_start +
					//		pmd_aligned_len - ((r->nr_thps) << 21);
					pmd_aligned_len = (r->nr_thps) << 21;
				}

				if (remaining_demote_sz < pmd_aligned_len) {
					pmd_aligned_start = pmd_aligned_start + pmd_aligned_len - remaining_demote_sz;
					pmd_aligned_len = remaining_demote_sz;
				}

				//	Demote non-hot page table pages (ZS)
				//	damo_tlbh_demote_memory_region(mm, pmd_aligned_start,
				//			pmd_aligned_start + pmd_aligned_len);

				// Write the gfns to shared memory (demote)
				if (t->tlbh_ivshmem_base) {
                		        tlbh_write_gfns_range(mm, pmd_aligned_start,
							pmd_aligned_start + pmd_aligned_len,
								t->tlbh_ivshmem_base, 0);
                		}

				if (quota->charged_sz <= pmd_aligned_len)
					quota->charged_sz = 0;
				else
					quota->charged_sz -= pmd_aligned_len;

				if (remaining_demote_sz < (r->nr_thps << 21)) {
					r->nr_thps -= remaining_demote_sz >> 21;
				} else {
					r->nr_thps = 0;
				}

				// Break the loop if the quota is enough
				if (quota->charged_sz + cumulated_promote_sz
						<= quota->esz)
					break;
		       }
	       }
	       ++demote_score;
	}

	// Promotion starts after possible demotions (ZS)
	damon_tlbh_for_each_intention_promote_region(r, t) {
		
		if (i < t->nr_intention_promote_regions) {
			pmd_aligned_start = ALIGN(r->ar.start, HPAGE_PMD_SIZE);
			pmd_aligned_len = damon_tlbh_effective_sz_region(r);

			if (r->nr_thps > 0) {
				pmd_aligned_start += (r->nr_thps) << 21;
				pmd_aligned_len = pmd_aligned_len - ((r->nr_thps) << 21);
			}

			if (trail_flag)
				pmd_aligned_len = div64_ul(((pmd_aligned_len >> 21) - r->nr_thps), 10)
							<< 21;

			if (likely(pmd_aligned_start <
				ALIGN_DOWN(r->ar.end, HPAGE_PMD_SIZE))) {

				if (ALIGN_DOWN(r->ar.end, HPAGE_PMD_SIZE) - pmd_aligned_start <
						pmd_aligned_len)
					pmd_aligned_len = ALIGN_DOWN(r->ar.end, HPAGE_PMD_SIZE) - pmd_aligned_start;

				// Get the page table address of the region (ZS)

				//	do_madvise(mm, pmd_aligned_start, pmd_aligned_len, MADV_COLLAPSE);
				//	hotgpt_promote_pgtable_page(mm, pmd_aligned_start, pmd_aligned_start + pmd_aligned_len);
				// Write the gfns to shared memory (promote)
				if (t->tlbh_ivshmem_base) {
					tlbh_write_gfns_range(mm, pmd_aligned_start,
							pmd_aligned_start + pmd_aligned_len,
							t->tlbh_ivshmem_base, 1);
				}

				quota->charged_sz += pmd_aligned_len;
				r->nr_thps += pmd_aligned_len >> 21;
				++i;
			}
		}

	}

	if (!trail_flag) {

		damon_tlbh_for_each_intention_promote_region_safe(r, next_r, t) {

			list_del(&r->intention_promote_node);

		}
		// Vacate the intention_promote_queue
		// for next round of use. (ZS)
		
		t->nr_intention_promote_regions = 0;

	}

	mmput(mm);

	if (t->tlbh_ivshmem_base) {
                memunmap(t->tlbh_ivshmem_base);
               	kvm_hypercall1(KVM_HC_TLBH_HOST_ALIGN, 1);
        }

	//	pr_warn("reallocated charged_sz: %lu\n", quota->charged_sz);

}

static void damon_check_intention_promote(struct damon_ctx *context)
{

	struct damon_target *t;

	struct damos *s;
	struct damos_quota *quota = NULL;

	//	static u64 first_cycles[MAX_PROFILE_THREAD], second_cycles[MAX_PROFILE_THREAD];
	static u64 first_cycles_total = 0UL, second_cycles_total = 0UL;

	//	static u64 first_instrs[MAX_PROFILE_THREAD], second_instrs[MAX_PROFILE_THREAD];
	static u64 first_instrs_total = 0UL, second_instrs_total = 0UL;

	u64 enabled, running;

	damon_for_each_scheme(s, context) {
		if ( s->action == DAMOS_TLBH ) {
			quota = &s->quota;
			break;
		}
	}

	// Do nothing if DAMOS_TLBH is not set as
	// one of a scheme
	if (!quota)
		return;

	// Iterate through each target in the context
	damon_for_each_target(t, context) {

		// Amount of aggregate intervals
	        // to pass before calling reset_aggregated (ZS)
	        static int num_intervals = 2;

		int i;

		bool create_flag = true;

		if (!(t->in_first_profiling) && !(t->in_second_profiling)
				&& !(t->finish_first_profiling)) {


			if (t->nr_intention_promote_regions <= 0) {

				continue;
			}

			if (!damon_get_task_structs(t)) {

				damon_put_task_structs(t);
				continue;
			}

			// Stop the queue insertion
			// before first round of profiling (ZS)
			t->allow_intention_insert = false;

			for (i = 0; i < t->nr_profile_thread; ++i) {
				// Start the first round profiling
				t->event_cycles1[i] = 
					perf_event_create_kernel_counter(&attr_cycles,
						-1, t->profile[i], NULL, NULL);
				t->event_cycles3[i] = 
					perf_event_create_kernel_counter(&attr_cycles1,
						-1, t->profile[i], NULL, NULL);
				t->event_instrs1[i] = 
					perf_event_create_kernel_counter(&attr_instrs,
						-1, t->profile[i], NULL, NULL);
				t->event_instrs3[i] = 
					perf_event_create_kernel_counter(&attr_instrs1,
						-1, t->profile[i], NULL, NULL);

				if ( !t->event_cycles1[i] ||
						IS_ERR(t->event_cycles1[i]) ||
						!(t->event_cycles1[i])->ctx ) {
					pr_warn("Failed to create perf event_cycles1: %ld\n",
							PTR_ERR(t->event_cycles1[i]));
					create_flag = false;
					break;
				}
				if ( !t->event_cycles3[i] ||
						IS_ERR(t->event_cycles3[i]) ||
						!(t->event_cycles3[i])->ctx ) {
					pr_warn("Failed to create perf event_cycles3: %ld\n",
							PTR_ERR(t->event_cycles3[i]));
					create_flag = false;
					break;
				}
				if ( !t->event_instrs1[i] ||
						IS_ERR(t->event_instrs1[i]) ||
						!(t->event_instrs1[i])->ctx ) {
					pr_warn("Failed to create perf event_instrs1: %ld\n",
							PTR_ERR(t->event_instrs1[i]));
					create_flag = false;
					break;
				}
				if ( !t->event_instrs3[i] ||
						IS_ERR(t->event_instrs3[i]) ||
						!(t->event_instrs3[i])->ctx ) {
					pr_warn("Failed to create perf event_instrs3: %ld\n",
							PTR_ERR(t->event_instrs3[i]));
					create_flag = false;
					break;
				}

			}

			if (!create_flag) {
				for (i = 0; i < t->nr_profile_thread; ++i) {
					if (!IS_ERR(t->event_cycles1[i]) && (t->event_cycles1[i])->ctx)
						perf_event_release_kernel(t->event_cycles1[i]);
					if (!IS_ERR(t->event_cycles3[i]) && (t->event_cycles3[i])->ctx)
						perf_event_release_kernel(t->event_cycles3[i]);
					if (!IS_ERR(t->event_instrs1[i]) && (t->event_instrs1[i])->ctx)
						perf_event_release_kernel(t->event_instrs1[i]);
					if (!IS_ERR(t->event_instrs3[i]) && (t->event_instrs3[i])->ctx)
						perf_event_release_kernel(t->event_instrs3[i]);
				}

				damon_put_task_structs(t);
				t->allow_intention_insert = true;
				continue;
			} else {
				for (i = 0; i < t->nr_profile_thread; ++i) {
					perf_event_enable(t->event_cycles1[i]);
					perf_event_enable(t->event_cycles3[i]);
					perf_event_enable(t->event_instrs1[i]);
					perf_event_enable(t->event_instrs3[i]);
				}
			}

			t->in_first_profiling = true;

		} else if (t->in_first_profiling) {
			
			if (num_intervals > 0) {
                                --num_intervals;
				continue;
                        }
                        else {
                                num_intervals = 2;
                        }

			for (i = 0; i < t->nr_profile_thread; ++i) {
				// Stop current profiling
				perf_event_disable(t->event_cycles1[i]);
				perf_event_disable(t->event_instrs1[i]);
				perf_event_disable(t->event_cycles3[i]);
				perf_event_disable(t->event_instrs3[i]);

				first_cycles_total += perf_event_read_value(t->event_cycles1[i], &enabled, &running);
				first_cycles_total += perf_event_read_value(t->event_cycles3[i], &enabled, &running);

				first_instrs_total += perf_event_read_value(t->event_instrs1[i], &enabled, &running);
				first_instrs_total += perf_event_read_value(t->event_instrs3[i], &enabled, &running);

				perf_event_release_kernel(t->event_cycles1[i]);
				perf_event_release_kernel(t->event_instrs1[i]);
				perf_event_release_kernel(t->event_cycles3[i]);
				perf_event_release_kernel(t->event_instrs3[i]);
			}

			do_hugepage_reallocate(context, t, s, quota, true);

			t->in_first_profiling = false;
			t->finish_first_profiling = true;

		} else if (t->finish_first_profiling) {
			
			if (num_intervals > 0) {
                                --num_intervals;
                                continue;
                        }
                        else {
                                num_intervals = 2;
                        }

			for (i = 0; i < t->nr_profile_thread; ++i) {
				// Start the second round profiling
				t->event_cycles2[i] = 
					perf_event_create_kernel_counter(&attr_cycles,
						-1, t->profile[i], NULL, NULL);
				t->event_cycles4[i] = 
					perf_event_create_kernel_counter(&attr_cycles1,
						-1, t->profile[i], NULL, NULL);
				t->event_instrs2[i] = 
					perf_event_create_kernel_counter(&attr_instrs,
						-1, t->profile[i], NULL, NULL);
				t->event_instrs4[i] = 
					perf_event_create_kernel_counter(&attr_instrs1,
						-1, t->profile[i], NULL, NULL);

				if ( !t->event_cycles2[i] ||
						IS_ERR(t->event_cycles2[i]) ||
						!(t->event_cycles2[i])->ctx ) {
					pr_warn("Failed to create perf event_cycles2: %ld\n",
							PTR_ERR(t->event_cycles2[i]));
					create_flag = false;
					break;
				}
				if ( !t->event_cycles4[i] ||
						IS_ERR(t->event_cycles4[i]) ||
						!(t->event_cycles4[i])->ctx ) {
					pr_warn("Failed to create perf event_cycles4: %ld\n",
							PTR_ERR(t->event_cycles4[i]));
					create_flag = false;
					break;
				}
				if ( !t->event_instrs2[i] ||
						IS_ERR(t->event_instrs2[i]) ||
						!(t->event_instrs2[i])->ctx ) {
					pr_warn("Failed to create perf event_instrs2: %ld\n",
							PTR_ERR(t->event_instrs2[i]));
					create_flag = false;
					break;
				}
				if ( !t->event_instrs4[i] ||
						IS_ERR(t->event_instrs4[i]) ||
						!(t->event_instrs4[i])->ctx ) {
					pr_warn("Failed to create perf event_instrs4: %ld\n",
							PTR_ERR(t->event_instrs4[i]));
					create_flag = false;
					break;
				}

			}

			if (!create_flag) {
				for (i = 0; i < t->nr_profile_thread; ++i) {
					if (t->event_cycles2[i] && (t->event_cycles2[i])->ctx)
						perf_event_release_kernel(t->event_cycles2[i]);
					if (t->event_cycles4[i] && (t->event_cycles4[i])->ctx)
						perf_event_release_kernel(t->event_cycles4[i]);
					if (t->event_instrs2[i] && (t->event_instrs2[i])->ctx)
						perf_event_release_kernel(t->event_instrs2[i]);
					if (t->event_instrs4[i] && (t->event_instrs4[i])->ctx)
						perf_event_release_kernel(t->event_instrs4[i]);
				}

				damon_put_task_structs(t);
				t->in_first_profiling = false;
				t->allow_intention_insert = true;
				continue;
			} else {
				for (i = 0; i < t->nr_profile_thread; ++i) {
					perf_event_enable(t->event_cycles2[i]);
					perf_event_enable(t->event_instrs2[i]);
					perf_event_enable(t->event_cycles4[i]);
					perf_event_enable(t->event_instrs4[i]);
				}
			}

			t->finish_first_profiling = false;
			t->in_second_profiling = true;

		} else if (t->in_second_profiling) {

			if (num_intervals > 0) {
                                --num_intervals;
                                continue;
                        }
                        else {
                                num_intervals = 2;
                        }

			for (i = 0; i < t->nr_profile_thread; ++i) {
				// Stop current profiling
				perf_event_disable(t->event_cycles2[i]);
				perf_event_disable(t->event_instrs2[i]);
				perf_event_disable(t->event_cycles4[i]);
				perf_event_disable(t->event_instrs4[i]);

				second_cycles_total += perf_event_read_value(t->event_cycles2[i], &enabled, &running);
				second_cycles_total += perf_event_read_value(t->event_cycles4[i], &enabled, &running);

				second_instrs_total += perf_event_read_value(t->event_instrs2[i], &enabled, &running);
				second_instrs_total += perf_event_read_value(t->event_instrs4[i], &enabled, &running);

				perf_event_release_kernel(t->event_cycles2[i]);
				perf_event_release_kernel(t->event_instrs2[i]);
				perf_event_release_kernel(t->event_cycles4[i]);
				perf_event_release_kernel(t->event_instrs4[i]);
			}

			damon_put_task_structs(t);

			// Promote the rest of the regions if performance
			// increased
			if (check_perf_improve(first_cycles_total, first_instrs_total,
						second_cycles_total, second_instrs_total)) {
			//	if (second_cycles_total < 
			//			first_cycles_total - div64_ul(first_cycles_total, 20)) {

				//	pr_warn("walk_completed_1:%llu, walk_completed_2:%llu\n",
				//			first_cycles_total, second_cycles_total);
				pr_warn("check_perf returns true.\n");
				do_hugepage_reallocate(context, t, s, quota, false);

			} else {

				struct damon_region *r, *next_r;

				damon_tlbh_for_each_intention_promote_region_safe(r, next_r, t) {

					list_del(&r->intention_promote_node);

				}

				t->nr_intention_promote_regions = 0;
				
			}

			first_cycles_total = 0UL;
			second_cycles_total = 0UL;
			first_instrs_total = 0UL;
			second_instrs_total = 0UL;

			t->cumulated_2MB_regions = 0UL;
			t->cumulated_trail_2MB_regions = 0UL;
			t->in_second_profiling = false;
			t->allow_intention_insert = true;

		}
	}


}
#endif	/* CONFIG_ADVISE_SYSCALLS */

static unsigned long damon_va_apply_scheme(struct damon_ctx *ctx,
		struct damon_target *t, struct damon_region *r,
		struct damos *scheme)
{
	int madv_action;

	switch (scheme->action) {
	case DAMOS_WILLNEED:
		madv_action = MADV_WILLNEED;
		break;
	case DAMOS_COLD:
		madv_action = MADV_COLD;
		break;
	case DAMOS_PAGEOUT:
		madv_action = MADV_PAGEOUT;
		break;
	case DAMOS_HUGEPAGE:
		madv_action = MADV_HUGEPAGE;
		break;
	case DAMOS_NOHUGEPAGE:
		madv_action = MADV_NOHUGEPAGE;
		break;
	case DAMOS_STAT:
		return 0;
	case DAMOS_TLBH:
	case DAMOS_GEMINI:
	//	case DAMOS_TLBH_OVH:
		return do_damos_tlbh(t, r, &scheme->quota);
	default:
		/*
		 * DAMOS actions that are not yet supported by 'vaddr'.
		 */
		return 0;
	}

	return damos_madvise(t, r, madv_action);
}

static int damon_va_scheme_score(struct damon_ctx *context,
		struct damon_target *t, struct damon_region *r,
		struct damos *scheme)
{

	switch (scheme->action) {
	case DAMOS_PAGEOUT:
		return damon_cold_score(context, r, scheme);
	case DAMOS_TLBH:
		return damon_tlbh_score(context, r, scheme);
	case DAMOS_GEMINI:
		return damon_gemini_score(context, r, scheme);
	//	case DAMOS_TLBH_OVH:
	//		return damon_tlbh_cold_score(context, r, scheme);
	default:
		break;
	}

	return DAMOS_MAX_SCORE;
}

static int __init damon_va_initcall(void)
{
	struct damon_operations ops = {
		.id = DAMON_OPS_VADDR,
		.init = damon_va_init,
		.update = damon_va_update,
		.prepare_access_checks = damon_va_prepare_access_checks,
		.check_accesses = damon_va_check_accesses,
		.reset_aggregated = damon_check_intention_promote,
		.target_valid = damon_va_target_valid,
		.cleanup = NULL,
		.apply_scheme = damon_va_apply_scheme,
		.get_scheme_score = damon_va_scheme_score,
	};
	/* ops for fixed virtual address ranges */
	struct damon_operations ops_fvaddr = ops;
	int err;

	/* Don't set the monitoring target regions for the entire mapping */
	ops_fvaddr.id = DAMON_OPS_FVADDR;
	ops_fvaddr.init = NULL;
	ops_fvaddr.update = NULL;

	err = damon_register_ops(&ops);
	if (err)
		return err;
	return damon_register_ops(&ops_fvaddr);
};

subsys_initcall(damon_va_initcall);

#include "vaddr-test.h"
