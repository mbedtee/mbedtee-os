// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Kernel VMA management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>

#include <device.h>
#include <vma.h>
#include <mmu.h>
#include <mem.h>
#include <page.h>
#include <kproc.h>

/*
 * Kernel Virtual Memory Address Space
 */
static struct vma *__kvmas;

/*
 * allocate contiguous kernel virtual space
 */
void *kvma_alloc(size_t size)
{
	if (!__kvmas)
		__kvmas = vma_create(KERN_VMA_START, KERN_VMA_SIZE, PAGE_SIZE);

	if (!__kvmas)
		return NULL;

	return vma_alloc(__kvmas, size);
}

/*
 * free the contiguous kernel virtual space
 */
void kvma_free(void *va)
{
	vma_free(__kvmas, va);
}

/*
 * return the num of bytes held by 'va' (aligned power of 2)
 */
size_t kvma_sizeof(void *va)
{
	return vma_sizeof(__kvmas, va);
}

void kvma_info(struct debugfs_file *d)
{
	debugfs_printf(d, "\nkvma info: size %lx, va: 0x%lx\n",
		(unsigned long)KERN_VMA_SIZE, KERN_VMA_START);

	if (__kvmas)
		vma_info(d, __kvmas);
}
