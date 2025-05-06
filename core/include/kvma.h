/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Kernel VMA management
 */

#ifndef _KVMA_H
#define _KVMA_H

#include <vma.h>

#if defined(CONFIG_MMU)
/*
 * allocate contiguous kernel virtual space
 */
void *kvma_alloc(size_t size);

/*
 * free the contiguous kernel virtual space
 */
void kvma_free(void *va);

/*
 * return the num of bytes held by 'va' (aligned power of 2)
 */
size_t kvma_sizeof(void *va);

void kvma_info(struct debugfs_file *d);

#else

static inline void *kvma_alloc(size_t size) {return NULL; }
static inline void kvma_free(void *va) {}
static inline size_t kvma_sizeof(void *va) {return 0; }
static inline void kvma_info(struct debugfs_file *d) {}

#endif

#endif
