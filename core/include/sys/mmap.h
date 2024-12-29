/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel level mmap() and munmap()
 */

#ifndef _SYS_MMAP_H
#define _SYS_MMAP_H

#include <list.h>
#include <errno.h>
#include <mmu.h>
#include <mmap.h>
#include <sections.h>

struct vm_struct {
	struct list_head node;
	struct file_desc *fdesc;
	struct pt_struct *pt;
	void *va;
	void *vapool;
	size_t length;
	off_t offset;
	const struct vm_operations *vm_ops;
	void *private_data;
	int prot;
};

struct vm_fault {
	off_t offset;
	struct page *page;
};

struct vm_operations {
	int (*fault)(struct vm_struct *vm, struct vm_fault *vf);
	void (*munmap)(struct vm_struct *vm);
};

void *vm_mmap(void *addr, size_t length, int prot,
			int flags, int fd, off_t offset);

int vm_munmap(void *addr, size_t length);

/*
 * resolved the process <-> mmap type
 */
struct process;
int vm_fault(struct process *proc, void *addr, int flags);

#endif
