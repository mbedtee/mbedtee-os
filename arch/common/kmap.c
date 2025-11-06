// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel memory map/unmap (with flexible flags)
 * device-IO map/unmap (None-Cacheable)
 */

#include <page.h>
#include <kvma.h>
#include <kproc.h>
#include <kmap.h>
#include <trace.h>
#include <rbtree.h>
#include <kmalloc.h>

#include <generated/autoconf.h>

/*
 * struct to linkup the VA, PA and SIZE informations
 */
struct vps {
	/* contiguous high virtual address */
	void *va;
	/* physical io/mem mapped to this va */
	unsigned long pa;
	size_t size;
	struct rb_node node;
};

#if defined(CONFIG_MMU)
static SPIN_LOCK(valock);
static struct rb_node *varoot;
#endif

static inline intptr_t va_rbfind_cmp(
	const void *addr, const struct rb_node *ref)
{
	struct vps *vm = rb_entry_of(ref, struct vps, node);

	if (addr >= vm->va && addr < vm->va + vm->size)
		return 0;

	return (addr < vm->va) ? -1 : 1;
}

static inline intptr_t va_rbadd_cmp(
	const struct rb_node *n, const struct rb_node *ref)
{
	return rb_entry_of(n, struct vps, node)->va <
		rb_entry_of(ref, struct vps, node)->va ? -1 : 1;
}

/*
 * return the kernel va address
 */
void *kmap(unsigned long pa, size_t size, int flags)
{
#if defined(CONFIG_MMU)
	void *va = NULL;
	struct vps *vm = NULL;
	unsigned long slflags = 0;

	if (pa && size) {
		if (((pa & (~PAGE_MASK)) + (size & (~PAGE_MASK))) > PAGE_SIZE)
			size += PAGE_SIZE;
		size = roundup(size, PAGE_SIZE);

		va = kvma_alloc(size);

		if (va) {
			vm = kzalloc(sizeof(struct vps));
			if (vm == NULL) {
				kvma_free(va);
				return NULL;
			}

			if (map(kpt(), rounddown(pa, PAGE_SIZE),
				va, size, flags) != 0) {
				kfree(vm);
				kvma_free(va);
				return NULL;
			}

			vm->va = va;
			vm->pa = pa;
			vm->size = size;
			spin_lock_irqsave(&valock, slflags);
			rb_add(&vm->node, &varoot, va_rbadd_cmp);
			spin_unlock_irqrestore(&valock, slflags);

			va += (pa % PAGE_SIZE);
		}
	}

	return va;
#endif /* CONFIG_MMU */

	return (void *)pa;
}

/*
 * unmap and free the va
 */
void kunmap(void *va)
{
#if defined(CONFIG_MMU)
	struct vps *vm = NULL;
	unsigned long slflags = 0;

	if (va) {
		spin_lock_irqsave(&valock, slflags);

		vm = rb_entry(rb_find(va, varoot, va_rbfind_cmp),
					struct vps, node);
		if (vm)
			rb_del(&vm->node, &varoot);

		spin_unlock_irqrestore(&valock, slflags);

		if (vm) {
			unmap(kpt(), vm->va, vm->size);
			kvma_free(vm->va);
			kfree(vm);
		}
	}
#endif
}

/*
 * return the non-cacheable IO address
 */
void *iomap(unsigned long pa, size_t size)
{
#if defined(CONFIG_MMU) && !defined(CONFIG_MIPS)
	return kmap(pa, size, PG_RW | PG_DMA);
#endif /* CONFIG_MMU -> CONFIG_ARM / CONFIG_RISCV */

#if defined(CONFIG_MIPS) /* MIPS has fix-mapping-table */
	return (void *)(UL(0xA0000000) | (pa));
#endif

	return (void *)pa;
}

/*
 * unmap and free the va
 */
void iounmap(void *va)
{
#if defined(CONFIG_MMU) && !defined(CONFIG_MIPS)
	return kunmap(va);
#endif
}
