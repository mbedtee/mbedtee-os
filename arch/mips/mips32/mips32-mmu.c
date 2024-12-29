// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MMU related functionalities for MIPS32 based SoCs.
 */

#include <io.h>
#include <mmu.h>
#include <init.h>
#include <list.h>
#include <kproc.h>
#include <sched.h>
#include <errno.h>
#include <trace.h>
#include <sleep.h>
#include <cache.h>
#include <sections.h>
#include <stdbool.h>
#include <percpu.h>
#include <thread.h>
#include <kmalloc.h>
#include <uaccess.h>
#include <spinlock.h>
#include <cacheops.h>

#include <mips32-mmu.h>
#include <mips32-tlb.h>

/*
 * kernel page table directories
 */
static ptd_t __kern_pgtbl[PTDS_PER_PT]
	__section(".bss") __aligned(PAGE_SIZE) = {0};

/* Process ASIDs - 256 */
static struct ida asida = {0};

static void __init init_asid(void)
{
	assert(ida_init(&asida, ASID_END) == 0);

	ida_set(&asida, 0);
}

static int map_page(struct pt_struct *pt,
	unsigned long pteval, unsigned long va)
{
	int ret = -ENOMEM;
	ptd_t *ptd = NULL;
	pte_t *pte = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&pt->lock, flags);

	pteval = phys_to_dma(pteval) | TLB_VALID;

	ptd = ptd_of(pt, va);
	if (ptd_null(ptd)) {
		ret = ptd_alloc(ptd);
		if (ret != 0)
			goto out;
	} else {
		ptd_hold(ptd);
	}

	pte = pte_of(ptd, va);
	if (pte_null(pte)) {
		pte_set(pte, pteval);
		/*
		 * for kernel va or current proc's va, this va might be
		 * accessed soon, so fill it to tlb for accelerating
		 */
		if ((pt == kpt()) || (current->proc->pt == pt))
			update_tlb_pte(pte, pt->asid, va);
		else
			flush_tlb_pte(pte, pt->asid, va);
	} else {
		ret = -EBUSY;
		ptd_put(ptd);
		goto out;
	}

	ret = 0;

out:
	spin_unlock_irqrestore(&pt->lock, flags);
	return ret;
}

static void unmap_page(struct pt_struct *pt, unsigned long va)
{
	ptd_t *ptd = NULL;
	pte_t *pte = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);

	if (!ptd_null(ptd)) {
		pte = pte_of(ptd, va);
		if (!pte_null(pte)) {
			pte_set(pte, 0);
			flush_tlb_pte(pte, pt->asid, va);

			if (ptd_refc(ptd) == 0)
				ptd_free(ptd);
			else
				ptd_put(ptd);
		}
	}

	spin_unlock_irqrestore(&pt->lock, flags);
}

static void map_setzero(struct pt_struct *pt,
	unsigned long pa, void *va)
{
	if (kpt() == pt)
		memset(va, 0, PAGE_SIZE);
	else if (pt == current->proc->pt)
		memset(va, 0, PAGE_SIZE);
	else {
		va = phys_to_virt(pa & PAGE_MASK);
		memset(va, 0, PAGE_SIZE);
	}
}

int map(struct pt_struct *pt, unsigned long pa, void *_va,
	unsigned long size, unsigned long flags)
{
	int ret = -ENOMEM, is_kern = (pt->asid == 0);
	unsigned long va = (unsigned long)_va, va_start = va;

	if ((flags & PG_ZERO) && !(flags & PG_RW)) {
		EMSG("PG_ZERO must with PG_RW\n");
		return -EINVAL;
	}

	if (KSEG0_REGION(va) || KSEG1_REGION(va)) {
		if (flags & PG_ZERO)
			memset((void *)va, 0, size);
		return 0;
	}

	if ((!va) || (!pa))
		return -EINVAL;

	if ((va & (~PAGE_MASK)) || (pa & (~PAGE_MASK))) {
		EMSG("pa/va isn't page-aligned\n");
		return -EINVAL;
	}

	if (size == 0)
		return 0;

	if (size & (~PAGE_MASK)) {
		EMSG("size isn't page-aligned\n");
		return -EINVAL;
	}

	if (is_kern)
		pa |= TLB_GLOBAL;
	if (!(flags & PG_DMA))
		pa |= TLB_CACHE_WRITEBACK;
	if ((flags & PG_RW) == PG_RW)
		pa |= TLB_WRITEABLE;

	while (size) {
		if (is_kern == user_addr(va)) {
			ret = -EACCES;
			goto out;
		}

		ret = map_page(pt, pa, va);
		if (ret)
			goto out;

		if (flags & PG_ZERO)
			map_setzero(pt, pa, (void *)va);

		va += PAGE_SIZE;
		pa += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

out:
	if (ret)
		unmap(pt, (void *)va_start, va - va_start);

	return ret;
}

void unmap(struct pt_struct *pt, void *_va, unsigned long size)
{
	unsigned long va = (unsigned long)_va;

	if (KSEG0_REGION(va) || KSEG1_REGION(va))
		return;

	if (!va || !size)
		return;

	if ((va & (~PAGE_MASK)) || (size & (~PAGE_MASK))) {
		EMSG("va/size isn't page-aligned\n");
		return;
	}

	while (size) {
		unmap_page(pt, va);
		va += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
}

unsigned long user_virt_to_phys(void *va)
{
	return user_virt_to_phys_pt(current->proc->pt, va);
}

unsigned long user_virt_to_phys_pt(struct pt_struct *pt, void *_va)
{
	ptd_t *ptd = NULL;
	pte_t *pte = NULL;
	unsigned long pa = 0, va = (long)_va;
	unsigned long flags = 0;

	local_irq_save(flags);
	ptd = ptd_of(pt, va);
	if (!ptd_null(ptd)) {
		pte = pte_of(ptd, va);
		pa = pte->val & (TLB_PFN_MASK << TLB_PFN_SHIFT);
		if (pa)
			pa = dma_to_phys(pa);
	}
	local_irq_restore(flags);

	return pa ? (pa | (va &	(~PAGE_MASK))) : 0;
}

/*
 * shall acquire the spinlock out of this func
 */
static int arch_access_ok(struct pt_struct *pt,
	const void *addr, size_t size, int prot)
{
	ptd_t *ptd = NULL;
	pte_t *pte = NULL;
	size_t checked = 0;
	unsigned long pteval = 0;
	unsigned long va = (unsigned long)addr;

	while (checked < size) {
		ptd = ptd_of(pt, va + checked);
		if (ptd_null(ptd))
			return false;

		pte = pte_of(ptd, va + checked);
		pteval = pte->val;
		if (!pteval || ((prot == PG_RW) &&
			!(pteval & TLB_WRITEABLE)))
			return false;

		checked += PAGE_SIZE;
	}

	return true;
}

/*
 * access ok checks if the user
 * address range is accessible or not
 * according to the expected access flags
 */
int access_user_ok(const void *addr, size_t size,
	int prot)
{
	int ret = false;
	unsigned long flags = 0;
	struct pt_struct *pt = current->proc->pt;

	if (!access_ok(addr, size))
		return false;

	spin_lock_irqsave(&pt->lock, flags);

	ret = arch_access_ok(pt, addr, size, prot);

	spin_unlock_irqrestore(&pt->lock, flags);

	return ret;
}

/*
 * access ok checks if the kernel
 * address range is accessible or not
 * according to the expected access flags
 */
int access_kern_ok(const void *addr, size_t size,
	int prot)
{
	int ret = false;
	unsigned long flags = 0;
	struct pt_struct *pt = kpt();

	if (KSEG0_REGION(addr) || KSEG1_REGION(addr))
		return true;

	if (access_ok(addr, size))
		return false;

	spin_lock_irqsave(&pt->lock, flags);

	ret = arch_access_ok(pt, addr, size, prot);

	spin_unlock_irqrestore(&pt->lock, flags);

	return ret;
}

static void alloc_asid(struct pt_struct *pt)
{
	int asid = ida_alloc(&asida);

	if (asid <= 0) {
		DMSG("ASID not enough\n");
		asid = ASID_RESVD; /* reserved for emergency */
	}

	pt->asid = asid;
}

static void free_asid(struct pt_struct *pt)
{
	if (ASID_VALID(pt->asid))
		ida_free(&asida, pt->asid);
}

/*
 * release resource from user process
 */
static void unmap_cleanup(struct pt_struct *pt)
{
	ptd_t *ptd = pt->ptds;
	size_t nr = USER_VA_TOP >> PTD_SHIFT;

	do {
		if (!ptd_null(ptd))
			ptd_free(ptd);
		ptd++;
	} while (--nr);
}

/*
 * allocate page table for process
 */
int alloc_pt(struct process *proc)
{
	struct pt_struct *pt = NULL;
	ptd_t *ptds = NULL;

	pt = kmalloc(sizeof(struct pt_struct));
	if (!pt)
		return -ENOMEM;

	spin_lock_init(&pt->lock);

	ptds = pages_alloc_continuous(PG_RW | PG_ZERO,
				PT_SIZE >> PAGE_SHIFT);
	if (!ptds)
		goto err;

	alloc_asid(pt);
	pt->ptds = ptds;
	pt->proc = proc;
	proc->pt = pt;

	return 0;

err:
	pages_free_continuous(ptds);
	kfree(pt);
	return -ENOMEM;
}

void free_pt(struct pt_struct *pt)
{
	if (pt && pt != kpt()) {
		unmap_cleanup(pt);
		free_asid(pt);
		pages_free_continuous(pt->ptds);
		kfree(pt);
	}
}

unsigned long mmu_section_size(void)
{
	return SECTION_SIZE;
}

int __init map_early(unsigned long pa,	size_t size, unsigned long flags)
{
	return 0;
}

void __init mmu_init_kpt(struct pt_struct *pt)
{
	pt->ptds = __kern_pgtbl;
	pt->lock = SPIN_LOCK_INIT(0);
	pt->proc = kproc();
	pt->refc = NULL;
	pt->asid = 0;
}

void __init mmu_init(void)
{
	init_asid();
	tlb_invalidate_all();
}
