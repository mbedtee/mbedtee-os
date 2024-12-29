/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel heap operations on the contiguous virtual
 * address space mmaped with scattered pages
 */

#ifndef _VMALLOC_H
#define _VMALLOC_H

#include <stddef.h>
#include <kmalloc.h>

#if defined(CONFIG_VMALLOC)

/*
 * allocate contiguous kernel virtual space,
 * allocate the scattered pages, and map the pages to
 * this contiguous kernel virtual space
 *
 * return the address of this kernel virtual space
 */
void *vmalloc(size_t size);

/*
 * free contiguous kernel virtual space,
 * free the scattered pages, and unmap the pages from
 * this contiguous kernel virtual space
 */
void vfree(void *va);

/*
 * vfree or kfree based on the input address
 */
void kvfree(void *va);

/*
 * allocate contiguous kernel virtual space,
 * allocate the scattered pages, and map the pages to
 * this contiguous kernel virtual space, memset this
 * kernel virtual space to zero
 *
 * return the address of this kernel virtual space
 */
void *vzalloc(size_t size);

#else
static inline void *vmalloc(size_t size) {return NULL; }
static inline void *vzalloc(size_t size) {return NULL; }
static inline void vfree(void *va) {}
static inline void kvfree(void *va) {kfree(va); }
#endif

#endif
