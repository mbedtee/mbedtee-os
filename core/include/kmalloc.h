/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel heaps operations on the contiguous physical pages
 */

#ifndef _KMALLOC_H
#define _KMALLOC_H

#include <stddef.h>
#include <stdbool.h>
#include <debugfs.h>

void *kmalloc(size_t size);
void *kzalloc(size_t size);
void *kcalloc(size_t n, size_t size);
void *krealloc(void *oldp, size_t size);
void kfree(const void *addr);

int kmalloc_early_init(void);
int kmalloc_post_init(void);

/*
 * release the cached idle pools after #usecs,
 * By set the #usecs to 0, it returns the pages to
 * page-pool immediately (retval: number of pages)
 */
size_t kmalloc_release(unsigned int usecs);

void kmalloc_info(struct debugfs_file *d);

#endif
