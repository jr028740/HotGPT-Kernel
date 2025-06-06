#ifndef _HUGEGPT_H
#define _HUGEGPT_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/list.h>

struct hgpt_segment {
    struct list_head head;
    unsigned long start;  /* [start, end) */
    unsigned long end;
};

enum hgpt_pt {
    P4D,
    PUD,
    PMD,
    PTE
};

void __init hgpt_init(void);

struct page *hgpt_page_alloc(struct mm_struct *mm, gfp_t gfp, int order, enum hgpt_pt pt);

bool hgpt_page_free(struct page *page);

#endif /* _HUGEGPT_H */
