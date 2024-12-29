/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * page operations
 */

#ifndef _PAGE_H
#define _PAGE_H

#include <defs.h>

/*
 * the page mapping's access permission
 */
#define PG_NONE    (0x00u)    /* meaning-less */
#define PG_RO      (0x01u)    /* read-only */
#define PG_RW      (0x03u)    /* read-write */
#define PG_DMA     (0x0100u)  /* non-cacheable mapping */
#define PG_EXEC    (0x0200u)  /* Executable */
#define PG_ZERO    (0x0400u)  /* memset to 0 after mapped */
#define PG_POOL    (0x0800u)  /* specific for kmalloc pools */

/*
 * page size
 */
#define PAGE_SHIFT              12
#define PAGE_SIZE               (UL(1) << PAGE_SHIFT)
#define PAGE_MASK				((unsigned long)(~(PAGE_SIZE - 1)))

/*
 * aligned on a page boundary
 */
#define page_aligned(x)	(((unsigned long)(x) & (~PAGE_MASK)) == 0)

#ifndef __ASSEMBLY__

#include <mmu.h>
#include <atomic.h>
#include <debugfs.h>

struct page {
	/* reference counter of this page */
	struct atomic_num refc;
};

/*
 * get the kernel virtual address
 */
void *page_address(struct page *p);

/*
 * initialize page allocator
 */
int page_pool_add(unsigned long start, unsigned long size);

/*
 * map one page to va
 * get this page
 */
int page_map(struct page *p, struct pt_struct *pt,
	void *va, unsigned long flags);

/*
 * unmap one page from va
 * put this page
 */
void page_unmap(struct page *p, struct pt_struct *pt,
	void *va);

/*
 * allocate one page
 */
struct page *page_alloc(void);

/*
 * free one page
 */
void page_free(struct page *p);

/*
 * increase the page reference count
 */
void page_get(struct page *p);

/*
 * decrease the page reference count
 * free it if reference count equal to zero
 */
void page_put(struct page *p);

/*
 * allocate 'num' of contiguous pages, 'num' shall be power of 2
 * return the kernel virtual address
 */
void *pages_alloc_continuous(unsigned long flags, unsigned long num);

/*
 * free contiguous pages, start from 'va'
 */
void pages_free_continuous(void *va);

int pin_user_pages(unsigned long start, int nr_pages, struct page **pages);

void unpin_user_pages(struct page **pages, int nr_pages);

size_t pages_sizeof(struct page *p);

/*
 * page to physical address
 */
unsigned long page_to_phys(struct page *p);

/*
 * physical address to page
 */
struct page *phys_to_page(unsigned long pa);

#define virt_to_page(va) phys_to_page(virt_to_phys(va))
#define page_to_virt(pg) phys_to_virt(page_to_phys(pg))

size_t nr_free_pages(void);

size_t nr_continuous_free_pages(void);

void page_info(struct debugfs_file *d);

#endif
#endif
