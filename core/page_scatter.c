// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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
	size_t i = 0;
	struct page **pages = NULL;

	if (num == 0)
		return NULL;

	pages = kcalloc(num, sizeof(struct page *));
	if (pages == NULL)
		return NULL;

	for (i = 0; i < num; i++) {
		pages[i] = page_alloc();
		if (pages[i] == NULL)
			goto out;
	}

	return pages;

out:
	pages_sc_free(pages, i);
	return NULL;
}

/*
 * free num of pages located in the pages[] arrays
 */
void pages_sc_free(struct page *pages[], size_t num)
{
	size_t i = 0;
	struct page *p = NULL;

	if (pages == NULL)
		return;

	for (i = 0; i < num; i++) {
		p = pages[i];
		if (p != NULL)
			page_free(p);
		else
			break;
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

	if ((va == NULL) || (num == 0))
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

	if ((pages == NULL) || (va == NULL) || (num == 0))
		return;

	for (i = 0; i < num; i++) {
		page_unmap(pages[i], pt, va);
		va += PAGE_SIZE;
	}
}

/*
 * allocate 'num' of scatter pages
 * allocated scatter pages are located in 'head'
 */
int pages_list_alloc(
	struct list_head *head, size_t num)
{
	size_t i = 0;
	struct scatter_page *sp = NULL;

	if (num == 0)
		return -EINVAL;

	for (i = 0; i < num; i++) {
		sp = kmalloc(sizeof(struct scatter_page));
		if (!sp)
			goto out;

		sp->page = page_alloc();
		if (!sp->page) {
			kfree(sp);
			goto out;
		}

		memset(page_address(sp->page), 0, PAGE_SIZE);
		list_add_tail(&sp->node, head);
	}

	return 0;

out:
	pages_list_free(head, i);
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
	size_t i = 0;
	struct scatter_page *sp = NULL;
	void *va_ori = va;

	if (va == NULL || num == 0 || list_empty(head))
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
	pages_list_unmap(&sp->node, pt, va_ori, i);
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

	if (va == NULL || num == 0)
		return;

	va += num << PAGE_SHIFT;

	list_for_each_entry_reverse(sp, head, node) {
		if (i++ >= num)
			break;
		va -= PAGE_SIZE;
		page_unmap(sp->page, pt, va);
	}
}
