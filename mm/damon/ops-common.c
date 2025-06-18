// SPDX-License-Identifier: GPL-2.0
/*
 * Common Primitives for Data Access Monitoring
 *
 * Author: SeongJae Park <sj@kernel.org>
 */

#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>

#include "ops-common.h"

/*
 * Get an online page for a pfn if it's in the LRU list.  Otherwise, returns
 * NULL.
 *
 * The body of this function is stolen from the 'page_idle_get_page()'.  We
 * steal rather than reuse it because the code is quite simple.
 */
struct page *damon_get_page(unsigned long pfn)
{
	struct page *page = pfn_to_online_page(pfn);

	if (!page || !PageLRU(page) || !get_page_unless_zero(page))
		return NULL;

	if (unlikely(!PageLRU(page))) {
		put_page(page);
		page = NULL;
	}
	return page;
}

void damon_ptep_mkold(pte_t *pte, struct vm_area_struct *vma, unsigned long addr)
{
	bool referenced = false;
	struct page *page = damon_get_page(pte_pfn(*pte));

	if (!page)
		return;

	if (ptep_test_and_clear_young(vma, addr, pte))
		referenced = true;

#ifdef CONFIG_MMU_NOTIFIER
	if (mmu_notifier_clear_young(vma->vm_mm, addr, addr + PAGE_SIZE))
		referenced = true;
#endif /* CONFIG_MMU_NOTIFIER */

	if (referenced)
		set_page_young(page);

	set_page_idle(page);
	put_page(page);
}

void damon_pmdp_mkold(pmd_t *pmd, struct vm_area_struct *vma, unsigned long addr)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	bool referenced = false;
	struct page *page = damon_get_page(pmd_pfn(*pmd));

	if (!page)
		return;

	if (pmdp_test_and_clear_young(vma, addr, pmd))
		referenced = true;

#ifdef CONFIG_MMU_NOTIFIER
	if (mmu_notifier_clear_young(vma->vm_mm, addr, addr + HPAGE_PMD_SIZE))
		referenced = true;
#endif /* CONFIG_MMU_NOTIFIER */

	if (referenced)
		set_page_young(page);

	set_page_idle(page);
	put_page(page);
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
}

void damon_nonleaf_pmdp_mkold(pmd_t *pmd, struct vm_area_struct *vma, unsigned long addr)
{
	if (pmd_young(*pmd)) {
		test_and_clear_bit(_PAGE_BIT_ACCESSED,
				(unsigned long *)pmd);
	}

#ifdef CONFIG_MMU_NOTIFIER
	mmu_notifier_clear_young(vma->vm_mm, addr, addr + HPAGE_PMD_SIZE);
#endif /* CONFIG_MMU_NOTIFIER */

}

#define DAMON_MAX_SUBSCORE	(100)
#define DAMON_MAX_AGE_IN_LOG	(32)

int damon_hot_score(struct damon_ctx *c, struct damon_region *r,
			struct damos *s)
{
	int freq_subscore;
	unsigned int age_in_sec;
	int age_in_log, age_subscore;
	unsigned int freq_weight = s->quota.weight_nr_accesses;
	unsigned int age_weight = s->quota.weight_age;
	int hotness;

	freq_subscore = r->nr_accesses * DAMON_MAX_SUBSCORE /
		damon_max_nr_accesses(&c->attrs);

	age_in_sec = (unsigned long)r->age * c->attrs.aggr_interval / 1000000;
	for (age_in_log = 0; age_in_log < DAMON_MAX_AGE_IN_LOG && age_in_sec;
			age_in_log++, age_in_sec >>= 1)
		;

	/* If frequency is 0, higher age means it's colder */
	if (freq_subscore == 0)
		age_in_log *= -1;

	/*
	 * Now age_in_log is in [-DAMON_MAX_AGE_IN_LOG, DAMON_MAX_AGE_IN_LOG].
	 * Scale it to be in [0, 100] and set it as age subscore.
	 */
	age_in_log += DAMON_MAX_AGE_IN_LOG;
	age_subscore = age_in_log * DAMON_MAX_SUBSCORE /
		DAMON_MAX_AGE_IN_LOG / 2;

	hotness = (freq_weight * freq_subscore + age_weight * age_subscore);
	if (freq_weight + age_weight)
		hotness /= freq_weight + age_weight;
	/*
	 * Transform it to fit in [0, DAMOS_MAX_SCORE]
	 */
	hotness = hotness * DAMOS_MAX_SCORE / DAMON_MAX_SUBSCORE;

	return hotness;
}

int damon_cold_score(struct damon_ctx *c, struct damon_region *r,
			struct damos *s)
{
	int hotness = damon_hot_score(c, r, s);

	/* Return coldness of the region */
	return DAMOS_MAX_SCORE - hotness;
}

int damon_tlbh_score(struct damon_ctx *c, struct damon_region *r,
			struct damos *s)
{
	unsigned int max_nr_accesses = 0;
	int hotness;

	if (c->ops.check_accesses)
		max_nr_accesses = c->ops.check_accesses(c);

	if (max_nr_accesses == 0)
		return 0;

	hotness = r->nr_accesses * DAMON_MAX_SUBSCORE / max_nr_accesses;

	return hotness * DAMOS_MAX_SCORE / DAMON_MAX_SUBSCORE;

}

int damon_tlbh_cold_score(struct damon_ctx *c, struct damon_region *r,
			struct damos *s)
{

	int hotness = damon_tlbh_score(c, r, s);
	return DAMOS_MAX_SCORE - hotness;
}

static inline int damon_gemini_rand(void)

{
	static unsigned int seed = 1234;
	
	// Use linear-feedback shift register
	// to generate reproducible pseudo-random
	// numbers

	seed ^= seed >> 11;
	seed ^= seed << 21;
	seed ^= seed >> 31;

	return (int) (seed % (1 + DAMOS_MAX_SCORE));
}

int damon_gemini_score(struct damon_ctx *c, struct damon_region *r,
			struct damos *s)
{
	return damon_gemini_rand();

}
