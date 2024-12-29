// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel heap operations on the contiguous virtual address space
 * mmaped with scattered pages
 */

#include <errno.h>
#include <stdbool.h>
#include <vma.h>
#include <mmu.h>
#include <mem.h>
#include <kproc.h>
#include <percpu.h>
#include <rbtree.h>
#include <buddy.h>
#include <kvma.h>
#include <kmalloc.h>
#include <trace.h>
#include <page.h>
#include <page_scatter.h>

/*
 * struct to linkup the VA, SIZE and PAGES informations
 */
struct vsp {
	/* contiguous high virtual address */
	void *va;
	size_t nr_pages;
	/* phy pages mapped to this vm */
	struct page **pages;
	struct rb_node node;
};

static SPIN_LOCK(valock);
static struct rb_node *varoot;

static inline intptr_t vma_rbfind_cmp(
	const void *addr,
	const struct rb_node *ref)
{
	struct vsp *vm = rb_entry_of(ref, struct vsp, node);

	if (addr >= vm->va && addr < vm->va +
		(vm->nr_pages << PAGE_SHIFT))
		return 0;

	return (addr < vm->va) ? -1 : 1;
}

static inline intptr_t vma_rbadd_cmp(
	const struct rb_node *n,
	const struct rb_node *ref)
{
	return rb_entry_of(n, struct vsp, node)->va <
		rb_entry_of(ref, struct vsp, node)->va ? -1 : 1;
}

/*
 * allocate contiguous kernel virtual space,
 * allocate the scattered pages, and map the pages to
 * this contiguous kernel virtual space
 *
 * return the address of this kernel virtual space
 */
void *vmalloc(size_t size)
{
	void *va = NULL;
	size_t nr_pages = size >> PAGE_SHIFT;
	struct vsp *vm = NULL;
	unsigned long flags = 0;
	int ret = -1;

	if (size & (~PAGE_MASK))
		nr_pages++;

	vm = kzalloc(sizeof(struct vsp));
	if (!vm)
		return NULL;

	va = kvma_alloc(size);
	if (va) {
		vm->pages = pages_sc_alloc(nr_pages);
		if (vm->pages == NULL)
			goto out;

		ret = pages_sc_map(vm->pages, kpt(), va, nr_pages, PG_RW);
		if (ret)
			goto out1;

		vm->va = va;
		vm->nr_pages = nr_pages;
		spin_lock_irqsave(&valock, flags);
		rb_add(&vm->node, &varoot, vma_rbadd_cmp);
		spin_unlock_irqrestore(&valock, flags);
		return va;
	}

out1:
	pages_sc_free(vm->pages, nr_pages);
out:
	kvma_free(va);
	kfree(vm);
	return NULL;
}

/*
 * allocate contiguous kernel virtual space,
 * allocate the scattered pages, and map the pages to
 * this contiguous kernel virtual space, memset this
 * kernel virtual space to zero
 *
 * return the address of this kernel virtual space
 */
void *vzalloc(size_t size)
{
	void *addr = vmalloc(size);

	if (addr)
		memset(addr, 0, size);

	return addr;
}

/*
 * free contiguous kernel virtual space,
 * free the scattered pages, and unmap the pages from
 * this contiguous kernel virtual space
 */
void vfree(void *va)
{
	struct vsp *vm = NULL;
	unsigned long flags = 0;

	if (va) {
		spin_lock_irqsave(&valock, flags);

		vm = rb_entry(rb_find(va, varoot, vma_rbfind_cmp),
					struct vsp, node);
		if (vm)
			rb_del(&vm->node, &varoot);

		spin_unlock_irqrestore(&valock, flags);

		if (vm) {
			pages_sc_unmap(vm->pages, kpt(), vm->va, vm->nr_pages);
			pages_sc_free(vm->pages, vm->nr_pages);
			kvma_free(vm->va);
			kfree(vm);
		}
	}
}

void kvfree(void *va)
{
	unsigned long addr = (unsigned long)va;

	if (addr >= KERN_VMA_START && addr <=
		KERN_VMA_START + KERN_VMA_SIZE - 1)
		vfree(va);
	else
		kfree(va);
}
