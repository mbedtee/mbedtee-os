/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Virtual Memory Address Space management
 */

#ifndef _VMA_H
#define _VMA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mutex.h>
#include <stddef.h>
#include <debugfs.h>

struct vma {
	/*
	 * VMA space start
	 */
	void *start;

	/* sorted by size */
	struct rb_node *rbroot[4];

	/* sorted by address */
	struct rb_node *rbroota[4];

	void *last;

	struct spinlock lock;

	/*
	 * VMA space total size
	 */
	unsigned char size_order;
	unsigned char node_order;
};

/*
 * Create a VMA
 */
struct vma *vma_create(unsigned long start, size_t size, size_t node_size);

/*
 * Destroy a VMA
 */
void vma_destroy(struct vma *vm);

/*
 * allocate contiguous virtual space
 * return the address of this virtual space
 */
void *vma_alloc(struct vma *vm, size_t size);

/*
 * free contiguous virtual space
 */
void vma_free(struct vma *vm, void *va);

/*
 * return the num of bytes held by 'va' (aligned power of 2)
 */
size_t vma_sizeof(struct vma *vm, void *va);

void vma_info(struct debugfs_file *d, struct vma *vm);

#ifdef __cplusplus
}
#endif
#endif
