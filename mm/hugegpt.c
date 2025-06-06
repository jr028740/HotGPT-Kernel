/**
 *  HugeGPT Implementation
 *
 */

#include <linux/hugegpt.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/pagewalk.h>
#include <linux/rcupdate.h>
#include <linux/smp.h>
#include <linux/swap.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <asm/pgalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <uapi/linux/kvm_para.h>
#include <uapi/asm/kvm_para.h>

#define HGPT_DEBUG_ALLOC_FREE 0
#define HGPT_HC_KVM_OVERRIDE 0
#define HGPT_SEG_LEN_PRECENTAGE 1
#define HGPT_SEG_LEN_FIXED 0
#define HGPT_PROC_ENTRY "hugegpt"
#define HGPT_PROC_ENTRY_PERMISSION 0666

#define HGPT_PAGE_COUNT_TO_SIZE(page_count) (page_count * PAGE_SIZE / 1048576UL) 

static spinlock_t hgpt_lock;
static struct mutex hgpt_allocating_lock;
static struct page *hgpt_page_next = NULL;
static struct kmem_cache *hgpt_seg_cache = NULL;
static struct hgpt_segment *hgpt_seg_recent = NULL;
static struct list_head hgpt_seg_list;
static unsigned long hgpt_seg_len = 0;
static struct proc_dir_entry* hgpt_proc_entry = NULL;
static int hgpt_hc_map_err_trial = 0;
#if HGPT_DEBUG_ALLOC_FREE
static unsigned long hgpt_debug_err_count = 0;
#endif /* HGPT_DEBUG_ALLOC_FREE */

static unsigned long hgpt_stat_page_total = 0, hgpt_stat_page_avail = 0;
static unsigned long hgpt_stat_seg_total = 0;
static unsigned long hgpt_stat_alloc_p4d = 0, hgpt_stat_alloc_pud = 0, hgpt_stat_alloc_pmd = 0, hgpt_stat_alloc_pte = 0;
static unsigned long hgpt_stat_free_hit = 0, hgpt_stat_free_miss = 0;

/**
 *  Guest KVM support
*/
static int hgpt_hc_request(unsigned long pfn, unsigned long page_count, unsigned int hc) {
    //pr_info("HugeGPT: hgpt_hc_request: Making hypercall, pfn=%lu, page_count=%lu\n", ALIGN_DOWN(pfn, HPAGE_PMD_NR), ALIGN(page_count, HPAGE_PMD_NR));
    #if HGPT_HC_KVM_OVERRIDE
    pr_warn("HugeGPT: hgpt_hc_request: KVM override, returning success without making hypercall\n");
    return 0;
    #else
    return kvm_hypercall2(hc, ALIGN_DOWN(pfn, HPAGE_PMD_NR), ALIGN(page_count, HPAGE_PMD_NR));
    #endif /* HGPT_HC_KVM_OVERRIDE */
}

/**
 *  Proc file system
*/
static void* hgpt_proc_seq_start(struct seq_file *file, loff_t *pos) {
    seq_printf(file, "HugeGPT segments:\n");
    return seq_list_start(&hgpt_seg_list, *pos);
}

static void* hgpt_proc_seq_next(struct seq_file *file, void *v, loff_t *pos) {
    return seq_list_next(v, &hgpt_seg_list, pos);
}

static void hgpt_proc_seq_stop(struct seq_file *file, void *v) {
    #if HGPT_DEBUG_ALLOC_FREE
    /* Debug */
    struct page **page_next_p;
    struct page *page = hgpt_page_next;
    unsigned long page_list_len = 0;
    unsigned long eflags;
    spin_lock_irqsave(&hgpt_lock, eflags);
    while (page) {
        page_next_p = (struct page **) page_to_virt(page);
        page = *page_next_p;
        ++page_list_len;
    }
    #endif /* HGPT_DEBUG_ALLOC_FREE */

    seq_printf(file, "\nSegment count: %lu\n", hgpt_stat_seg_total);
    seq_printf(file, "Segment length: %lu\n", hgpt_seg_len);
    seq_printf(file, "Page count (free/allocated): %lu (%lu, %lu)\n", hgpt_stat_page_total, hgpt_stat_page_avail, hgpt_stat_page_total - hgpt_stat_page_avail);
    seq_printf(file, "Page allocation (P4D/PUD/PMD/PTE): %lu (%lu, %lu, %lu, %lu)\n", hgpt_stat_alloc_p4d + hgpt_stat_alloc_pud + hgpt_stat_alloc_pmd + hgpt_stat_alloc_pte, hgpt_stat_alloc_p4d, hgpt_stat_alloc_pud, hgpt_stat_alloc_pmd, hgpt_stat_alloc_pte);
    seq_printf(file, "Page free (hit/miss): %lu (%lu, %lu)\n", hgpt_stat_free_hit + hgpt_stat_free_miss, hgpt_stat_free_hit, hgpt_stat_free_miss);
    seq_printf(file, "Memory used: %lu MB\n", HGPT_PAGE_COUNT_TO_SIZE(hgpt_stat_page_total));
    seq_printf(file, "Host map request error detected: %d\n", hgpt_hc_map_err_trial);

    #if HGPT_DEBUG_ALLOC_FREE
    seq_printf(file, "(Debug) True page list length: %lu\n", page_list_len);
    seq_printf(file, "(Debug) Allocation/free error detected: %lu\n", hgpt_debug_err_count);
    spin_unlock_irqrestore(&hgpt_lock, eflags);
    #endif /* HGPT_DEBUG_ALLOC_FREE */

    return;
}

static int hgpt_proc_seq_show(struct seq_file *file, void *v) {
    struct hgpt_segment *seg;
	seg = list_entry(v, struct hgpt_segment, head);
	seq_printf(file, "PFN start/end: [%lx:%lx)\n", seg->start, seg->end);
	return 0;
}

static struct seq_operations hgpt_proc_seq_ops = {
    .start = hgpt_proc_seq_start,
    .next  = hgpt_proc_seq_next,
    .stop  = hgpt_proc_seq_stop,
    .show  = hgpt_proc_seq_show
};

static int hgpt_proc_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &hgpt_proc_seq_ops);
}

static ssize_t hgpt_proc_write(struct file *file, const char __user *user_buf, size_t size, loff_t *loff) {
    /* Omitted */
	return size;
}

static struct proc_ops hgpt_proc_ops = {
        .proc_open    = hgpt_proc_open,
        .proc_read    = seq_read,
        .proc_write   = hgpt_proc_write,
        .proc_lseek   = seq_lseek,
        .proc_release = seq_release,
};

static bool hgpt_proc_init(void) {
	/* Proc filesystem init, run once */
	hgpt_proc_entry = proc_create(HGPT_PROC_ENTRY, HGPT_PROC_ENTRY_PERMISSION, hgpt_proc_entry, &hgpt_proc_ops);
	if (!hgpt_proc_entry) {
		pr_err("HugeGPT: hgpt_proc_init: Unable to create proc fs entry\n");
	} else {
		pr_info("HugeGPT: hgpt_proc_init: Created /proc/"HGPT_PROC_ENTRY"\n");
	}
	return true;
}

/**
 *  Check if HugeGPT should handle the operation
*/
static bool hgpt_check(struct mm_struct *mm) {

	if (!hgpt_seg_cache || !mm || !mm->owner) {
		return false;
	}

	if (mm->owner->pid <= 1) {
		return false;
	}

	if (system_state != SYSTEM_RUNNING) {
		return false;
	}

	return true;
}

/**
 *  Take one page from front of the list
*/
static struct page *hgpt_page_take(void) {
    struct page *page;
    struct page **page_next_p;
    unsigned long eflags;

    spin_lock_irqsave(&hgpt_lock, eflags);

    page = hgpt_page_next;

    page_next_p = (struct page **) page_to_virt(page);
    hgpt_page_next = *page_next_p;
    *page_next_p = NULL;
    --hgpt_stat_page_avail;

    spin_unlock_irqrestore(&hgpt_lock, eflags);

    return page;
}

/**
 *  Put one page to front of the list
*/
static void __maybe_unused hgpt_page_put(struct page *page) {
    struct page **page_next_p;
    unsigned long eflags;

    #if HGPT_DEBUG_ALLOC_FREE
    /* Debug */
    struct page *page_curr = hgpt_page_next;
    while (page_curr) {
        if (page_curr == page) {
            pr_err("HugeGPT: hgpt_page_put: DEBUG: Page is allocated by someone else! pfn=%lu\n", page_to_pfn(page));
            dump_stack();
            ++hgpt_debug_err_count;
            return;
        }
        page_next_p = (struct page **) page_to_virt(page_curr);
        page_curr = *page_next_p;
    }
    #endif /* HGPT_DEBUG_ALLOC_FREE */

    page_next_p = (struct page **) page_to_virt(page);

    spin_lock_irqsave(&hgpt_lock, eflags);

    *page_next_p = hgpt_page_next;
    hgpt_page_next = page;
    ++hgpt_stat_page_avail;

    spin_unlock_irqrestore(&hgpt_lock, eflags);
}

/**
 *  Add new pages to front of the list
 *  Assume lock held
*/
static void hgpt_page_add(struct page *page, unsigned long len) {
    struct page **page_next_p;
    unsigned long page_i;

    //pr_info("HugeGPT: hgpt_page_add: Adding %lu pages to the list\n", len);
    hgpt_stat_page_total += len;
    hgpt_stat_page_avail += len;

    for (page_i = 0; page_i < len; ++page_i) {
        page_next_p = (struct page **) page_to_virt(page + page_i);
        *page_next_p = (struct page *) -1;    /* Ensure a fault */
        *page_next_p = (struct page *) 0;
        //pr_info("HugeGPT: hgpt_page_add: pfn=%lx, page_count=%d\n", page_to_pfn(page + page_i), page_count(page + page_i));
        if (page_i + 1 == len) {
            *page_next_p = hgpt_page_next;
            break;
        }
        *page_next_p = page + page_i + 1;
    }

    hgpt_page_next = page;
}

/**
 *  Create a new segment and add new pages to the list
*/
static bool hgpt_seg_create(void) {
    struct hgpt_segment *seg;
    struct page *page;
    int hc_ret, proc_init = 0;
    unsigned long eflags;

    /* Actual allocation is not locked */
    mutex_lock(&hgpt_allocating_lock);
    if (hgpt_hc_map_err_trial) {
        mutex_unlock(&hgpt_allocating_lock);
        return false;
    }
    if (hgpt_page_next) {
        mutex_unlock(&hgpt_allocating_lock);
        return true;
    }

    /* Allocate pages */
    page = alloc_contig_pages(hgpt_seg_len, GFP_PGTABLE_USER, numa_node_id(), NULL);
    if (!page) {
        pr_err("HugeGPT: hgpt_seg_create: Unable to allocate contigious pages\n");
        mutex_unlock(&hgpt_allocating_lock);
        return false;
    }

    /* Call do_madvise on the host */
    hc_ret = hgpt_hc_request(page_to_pfn(page), hgpt_seg_len, KVM_HC_HGPT_REQ_MAP);
    if (hc_ret) {
        pr_err("HugeGPT: hgpt_seg_create: Unable to request mapping on host, hc_ret=%d\n", hc_ret);
        if (!hgpt_seg_recent) {
            /* Host might does not support HGPT HC */
            pr_warn("HugeGPT: hgpt_seg_create: Host might not support HugeGPT hypercall\n");
            kmem_cache_destroy(hgpt_seg_cache);
            hgpt_seg_cache = NULL;
        }
        pr_warn("HugeGPT: hgpt_seg_create: Disabling future allocations\n");
        ++hgpt_hc_map_err_trial;  /* If allocated before, disable future functionalities */
        free_contig_range(page_to_pfn(page), hgpt_seg_len);
        mutex_unlock(&hgpt_allocating_lock);
        return false;
    }

    /* Create new segment */
    seg = kmem_cache_alloc(hgpt_seg_cache, GFP_KERNEL);
    if (!seg) {
        pr_err("HugeGPT: hgpt_seg_create: Unable to allocate a new segment\n");
        free_contig_range(page_to_pfn(page), hgpt_seg_len);
        mutex_unlock(&hgpt_allocating_lock);
        return false;
    }
    INIT_LIST_HEAD(&seg->head);
    seg->start = page_to_pfn(page);
    seg->end = seg->start + hgpt_seg_len;

    /* Add to list */
    spin_lock_irqsave(&hgpt_lock, eflags);
    hgpt_page_add(page, hgpt_seg_len);
    proc_init = !!hgpt_seg_recent;
    hgpt_seg_recent = seg;
    list_add_tail(&seg->head, &hgpt_seg_list);
    spin_unlock_irqrestore(&hgpt_lock, eflags);

    /* Gather pages on the host */
    hc_ret = hgpt_hc_request(page_to_pfn(page), hgpt_seg_len, KVM_HC_HGPT_REQ_GATHER);
    if (hc_ret) {
        pr_err("HugeGPT: hgpt_seg_create: Unable to request gathering on host, hc_ret=%d\n", hc_ret);
        pr_warn("HugeGPT: hgpt_seg_create: Finishing current allocation, but disabling future allocations\n");
        ++hgpt_hc_map_err_trial;  /* Page already added to the list, so let the process finish */
    }

    /* Unlock */
    mutex_unlock(&hgpt_allocating_lock);
    
    /* Init proc if recent seg was not present */
    if (!proc_init) {
        hgpt_proc_init();
    }

    pr_info("HugeGPT: hgpt_seg_create: New segment created, pfn=[%lx:%lx)\n", seg->start, seg->end);
    ++hgpt_stat_seg_total;
    return true;
}

/**
 *  Try to return one page to the segment
*/
static bool hgpt_seg_return(struct hgpt_segment *seg, struct page *page) {
    unsigned long pfn = page_to_pfn(page);

    if (pfn >= seg->start && pfn < seg->end) {
        /* Return the page */
        //pr_info("HugeGPT: hgpt_seg_return: Returning page, pfn=%lx, ref_count=%d\n", pfn, page_ref_count(page));
        #if HGPT_DEBUG_ALLOC_FREE
        if (page_ref_count(page) != 1) {
            pr_err("HugeGPT: hgpt_seg_return: DEBUG: Page is referenced by someone else! pfn=%lu, ref_count=%d\n", pfn, page_ref_count(page));
            dump_stack();
            ++hgpt_debug_err_count;
            return true;
        }
        #endif /* HGPT_DEBUG_ALLOC_FREE */
        hgpt_page_put(page);
        return true;
    }

    return false;
}

void __init hgpt_init(void) {
    /* KVM prerequisite check */
    if (!HGPT_HC_KVM_OVERRIDE && !kvm_para_available()) {
        pr_err("HugeGPT: hgpt_init: KVM paravirtualization is not available\n");
        return;
    } else if (HGPT_HC_KVM_OVERRIDE) {
        pr_warn("HugeGPT: hgpt_init: KVM override, skipping prerequisite check\n");
    }
    
    /* HugeGPT */
    spin_lock_init(&hgpt_lock);
    mutex_init(&hgpt_allocating_lock);
    hgpt_seg_len = ALIGN(max_pfn / 100 * HGPT_SEG_LEN_PRECENTAGE, HPAGE_PMD_NR);
    if (HGPT_SEG_LEN_FIXED) {
        hgpt_seg_len = HGPT_SEG_LEN_FIXED;
    }
    INIT_LIST_HEAD(&hgpt_seg_list);

    /* Slab cache */
    hgpt_seg_cache = kmem_cache_create("hgpt_segment", sizeof(struct hgpt_segment), 0, SLAB_PANIC, NULL);
    if (!hgpt_seg_cache) {
		pr_err("HugeGPT: hgpt_init: Segment cache is not ready\n");
        return;
	}

    pr_info("HugeGPT: hgpt_init: Welcome to HugeGPT Linux, max_pfn=%lu, hgpt_seg_len=%lu\n", max_pfn, hgpt_seg_len);
    #if HGPT_DEBUG_ALLOC_FREE
    pr_warn("HugeGPT: hgpt_init: Debugging HugeGPT allocation/free, performance will be degraded\n");
    #endif /* HGPT_DEBUG_ALLOC_FREE */

    return;
}

struct page *hgpt_page_alloc(struct mm_struct *mm, gfp_t gfp, int order, enum hgpt_pt pt) {
    struct page *page;

    if (!hgpt_check(mm)) {
        return NULL;
    }

    if (!hgpt_page_next && (hgpt_hc_map_err_trial || !hgpt_seg_create())) {
        return NULL;
    }

    /* Allocate page */
    page = hgpt_page_take();
    switch (pt) {
        case P4D:
            ++hgpt_stat_alloc_p4d;
            break;
        case PUD:
            ++hgpt_stat_alloc_pud;
            break;
        case PMD:
            ++hgpt_stat_alloc_pmd;
            break;
        case PTE:
            ++hgpt_stat_alloc_pte;
            break;
        default:;
    }

    //pr_info("HugeGPT: hgpt_page_alloc: Allocating page, pfn=%lx\n", page_to_pfn(page));

    return page;
}

bool hgpt_page_free(struct page *page) {
    struct list_head *curr_head;
    struct hgpt_segment *seg;

    if (!hgpt_seg_cache || !hgpt_seg_recent || !page) {
        return false;
    }

    /* Recent one first? */
    if (hgpt_seg_return(hgpt_seg_recent, page)) {
        ++hgpt_stat_free_hit;
        return true;
    }

    /* Iterate all segments */
    list_for_each(curr_head, &hgpt_seg_list) {
        seg = list_entry(curr_head, struct hgpt_segment, head);
        if (hgpt_seg_return(seg, page)) {
            hgpt_seg_recent = seg;
            ++hgpt_stat_free_miss;
            return true;
        }
    }
    
    return false;
}
EXPORT_SYMBOL(hgpt_page_free);
