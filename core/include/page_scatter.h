/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * scatter page operations
 */

#ifndef _PAGE_SC_H
#define _PAGE_SC_H

#include <stddef.h>
#include <list.h>
#include <page.h>

struct scatter_page {
	struct list_head node;
	struct page *page;
};

/*
 * allocate 'num' of scatter pages
 * allocated scatter pages are located in pages[]
 */
struct page **pages_sc_alloc(size_t num);
/*
 * free num of pages located in the pages[] arrays
 */
void pages_sc_free(struct page *pages[], size_t num);
/*
 * map num of pages located in the pages[] arrays
 */
int pages_sc_map(struct page *pages[], struct pt_struct *pt,
		void *va, size_t num, unsigned long flags);
/*
 * unmap num of pages located in the pages[] arrays
 */
void pages_sc_unmap(struct page *pages[], struct pt_struct *pt,
		void *va, size_t num);

/*
 * allocate 'num' of scatter pages
 * allocated scatter pages are located in tail of the list
 */
int pages_list_alloc(struct list_head *head, size_t num);
/*
 * free num of pages located in the specified scatter_page list
 */
void pages_list_free(struct list_head *head, size_t num);
/*
 * map num of pages located in the specified scatter_page list
 */
int pages_list_map(struct list_head *head, struct pt_struct *pt,
		void *va, size_t num, unsigned long flags);
/*
 * unmap num of pages located in the specified scatter_page list
 */
void pages_list_unmap(struct list_head *head, struct pt_struct *pt,
		void *va, size_t num);

#endif
