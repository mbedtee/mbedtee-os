// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * page map operations
 */

#include <mmu.h>
#include <page.h>
#include <errno.h>
#include <thread.h>

static int pages_map(struct page *p, struct pt_struct *pt,
	void *va, unsigned long nr, unsigned long flags)
{
	int ret = -ENOMEM;

	if ((!p) || (!pt) || (!va))
		return -EINVAL;

	if ((unsigned long)va & (~PAGE_MASK))
		return -EINVAL;

	page_get(p);

	ret = map(pt, page_to_phys(p), va, nr << PAGE_SHIFT, flags);
	if (ret != 0) {
		DMSG("map %p@%p error %d\n", p, va, ret);
		page_put(p);
	}

	return ret;
}

/*
 * map one page to va
 * get this page
 */
int page_map(struct page *p, struct pt_struct *pt,
	void *va, unsigned long flags)
{
	return pages_map(p, pt, va, 1, flags);
}

static void pages_unmap(struct page *p, struct pt_struct *pt,
	void *va, unsigned long nr)
{
	if ((!p) || (!va) || (!nr))
		return;

	if ((unsigned long)va & (~PAGE_MASK))
		return;

	unmap(pt, va, nr << PAGE_SHIFT);

	page_put(p);
}

/*
 * unmap one page to va
 * put this page
 */
void page_unmap(struct page *p, struct pt_struct *pt, void *va)
{
	pages_unmap(p, pt, va, 1);
}

int pin_user_pages(unsigned long start, int nr, struct page **pages)
{
	int cnt = 0;
	unsigned long phys = 0;
	struct page *p = NULL;
	struct pt_struct *pt = current->proc->pt;
	unsigned long flags = 0;

	spin_lock_irqsave(&pt->lock, flags);

	start = start & PAGE_MASK;

	for (cnt = 0; cnt < nr; cnt++) {
		phys = user_virt_to_phys((void *)start + (cnt * PAGE_SIZE));
		if (phys == 0)
			break;
		p = phys_to_page(phys);
		page_get(p);
		pages[cnt] = p;
	}

	spin_unlock_irqrestore(&pt->lock, flags);
	return cnt;
}

void unpin_user_pages(struct page **pages, int nr)
{
	int i = 0;

	for (i = 0; i < nr; i++)
		page_put(pages[i]);
}
