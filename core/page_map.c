// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * page map operations
 */

#include <mmu.h>
#include <page.h>
#include <errno.h>
#include <thread.h>

/*
 * map one page to va
 * get this page
 */
int page_map(struct page *p, struct pt_struct *pt,
	void *va, unsigned long flags)
{
	int ret = -ENOMEM;

	if (!p || !pt || !va)
		return -EINVAL;

	if ((unsigned long)va & (~PAGE_MASK))
		return -EINVAL;

	page_get(p);

	ret = map(pt, page_to_phys(p), va, PAGE_SIZE, flags);
	if (ret != 0) {
		DMSG("map %p@%p error %d\n", p, va, ret);
		page_put(p);
	}

	return ret;
}

/*
 * unmap one page from va
 * put this page
 */
void page_unmap(struct page *p, struct pt_struct *pt, void *va)
{
	if (!p || !va)
		return;

	if ((unsigned long)va & (~PAGE_MASK))
		return;

	unmap(pt, va, PAGE_SIZE);
	page_put(p);
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
