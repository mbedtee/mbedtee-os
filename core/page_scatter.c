// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * scatter page operations
 */

#include <list.h>
#include <page.h>
#include <trace.h>
#include <errno.h>
#include <kmalloc.h>

#include <page_scatter.h>

/*
 * allocate 'num' of scatter pages
 * allocated scatter pages are located in pages[]
 */
struct page **pages_sc_alloc(size_t num)
{
	struct page **pages = NULL;

	if (num == 0)
		return NULL;

	pages = kcalloc(num, sizeof(struct page *));
	if (!pages)
		return NULL;

	if (pages_batch_alloc(pages, num) != 0)
		goto out;

	return pages;

out:
	kfree(pages);
	return NULL;
}

/*
 * free num of pages located in the pages[] arrays
 */
void pages_sc_free(struct page *pages[], size_t num)
{
	size_t i = 0;
	struct page *p = NULL;

	if (!pages)
		return;

	for (i = 0; i < num; i++) {
		p = pages[i];
		if (!p)
			break;
		page_free(p);
	}

	kfree(pages);
}

/*
 * map num of pages located in the pages[] arrays
 */
int pages_sc_map(struct page *pages[], struct pt_struct *pt,
		void *va, size_t num, unsigned long flags)
{
	int ret = -1;
	size_t i = 0;
	void *va_ori = va;

	if (!va || num == 0)
		return -EINVAL;

	for (i = 0; i < num; i++) {
		ret = page_map(pages[i], pt, va, flags);
		if (ret != 0)
			goto out;
		va += PAGE_SIZE;
	}

	return 0;

out:
	pages_sc_unmap(pages, pt, va_ori, i);
	return ret;
}

/*
 * unmap num of pages located in the pages[] arrays
 */
void pages_sc_unmap(struct page *pages[], struct pt_struct *pt,
		void *va, size_t num)
{
	size_t i = 0;

	if (!pages || !va || num == 0)
		return;

	unmap(pt, va, num << PAGE_SHIFT);

	for (i = 0; i < num; i++)
		page_put(pages[i]);
}

/*
 * allocate 'num' of scatter pages
 * allocated scatter pages are located in 'head'
 */
int pages_list_alloc(
	struct list_head *head, size_t num)
{
	size_t i = 0;
	struct page **tmp = NULL;
	struct scatter_page *sp = NULL;

	if (num == 0)
		return -EINVAL;

	tmp = kcalloc(num, sizeof(struct page *));
	if (!tmp)
		return -ENOMEM;

	if (pages_batch_alloc(tmp, num) != 0) {
		kfree(tmp);
		return -ENOMEM;
	}

	for (i = 0; i < num; i++) {
		sp = kmalloc(sizeof(struct scatter_page));
		if (!sp)
			goto out;

		memset(page_address(tmp[i]), 0, PAGE_SIZE);
		sp->page = tmp[i];
		list_add_tail(&sp->node, head);
	}

	kfree(tmp);
	return 0;

out:
	/* free scatter_page nodes already added */
	pages_list_free(head, i);
	/* free pages not yet assigned to a node */
	for (; i < num; i++)
		page_free(tmp[i]);
	kfree(tmp);
	return -ENOMEM;
}

/*
 * free num of pages located in the specified scatter_page list
 */
void pages_list_free(struct list_head *head, size_t num)
{
	size_t i = 0;
	struct scatter_page *sp = NULL, *_n = NULL;

	list_for_each_entry_safe_reverse(sp, _n, head, node) {
		if (i++ >= num)
			break;
		list_del(&sp->node);
		page_free(sp->page);
		kfree(sp);
	}
}

/*
 * map num of pages located in the specified scatter_page list
 */
int pages_list_map(struct list_head *head, struct pt_struct *pt,
		void *va, size_t num, unsigned long flags)
{
	int ret = -1;
	size_t i = 0, j = 0;
	struct scatter_page *sp = NULL;
	void *va_ori = va;

	if (!va || num == 0 || list_empty(head))
		return -EINVAL;

	list_for_each_entry(sp, head, node) {
		if (i >= num)
			break;

		ret = page_map(sp->page, pt, va, flags);
		if (ret != 0)
			goto out;

		i++;
		va += PAGE_SIZE;
	}

	return 0;

out:
	unmap(pt, va_ori, i << PAGE_SHIFT);
	list_for_each_entry(sp, head, node) {
		if (j++ >= i)
			break;
		page_put(sp->page);
	}
	return ret;
}

/*
 * unmap num of pages located in the specified scatter_page list
 */
void pages_list_unmap(struct list_head *head, struct pt_struct *pt,
		void *va, size_t num)
{
	size_t i = 0;
	struct scatter_page *sp = NULL;

	if (!va || num == 0)
		return;

	unmap(pt, va, num << PAGE_SHIFT);

	list_for_each_entry_reverse(sp, head, node) {
		if (i++ >= num)
			break;
		page_put(sp->page);
	}
}
