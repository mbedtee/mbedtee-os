// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MMU related functionalities for AArch32@ARMV7-A based SoCs.
 */

#include <io.h>
#include <of.h>
#include <cpu.h>
#include <mmu.h>
#include <init.h>
#include <list.h>
#include <kproc.h>
#include <sched.h>
#include <errno.h>
#include <trace.h>
#include <sleep.h>
#include <cache.h>
#include <stdbool.h>
#include <sections.h>
#include <percpu.h>
#include <thread.h>
#include <kmalloc.h>
#include <uaccess.h>
#include <spinlock.h>
#include <cacheops.h>

#include "aarch32-mmu.h"

/*
 * kernel page table for TTBR1
 * aligned to 16K bytes (could map 4GB space)
 */
unsigned long __kern_pgtbl[PTDS_PER_KPT]
	__section(".bss")
	__aligned(16384) = {0};

/* Process ASIDs */
static struct ida asida = {0};

static void __init init_asid(void)
{
	assert(ida_init(&asida, ASID_END) == 0);

	ida_set(&asida, 0);
}

static int map_page(struct pt_struct *pt,
	unsigned long va, unsigned long ptdflag,
	unsigned long pteval)
{
	int ret = -ENOMEM;
	ptd_t *ptd = NULL;
	pte_t *pte = NULL;
	int newptd = false;
	unsigned long flags = 0;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);
	if (ptd_null(ptd)) {
		ret = ptd_alloc(ptd);
		if (ret != 0)
			goto out;
		newptd = true;
		ptd_setflags(ptd, ptdflag);
	} else {
		if (!ptd_type_page(ptd)) {
			ret = -EFAULT;
			goto out;
		}
	}

	pte = pte_of(ptd, va);
	if (pte_null(pte)) {
		if (newptd == false)
			ptd_hold(pt, va);
		pte_set(pte, pteval);
	} else {
		ret = -EEXIST;
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

	if (ptd_type_page(ptd)) {
		pte = pte_of(ptd, va);
		if (!pte_null(pte)) {
			pte_set(pte, 0);
			flush_tlb_pte(va, pt->asid);

			if (ptd_refc(pt, va) == 0)
				ptd_free(ptd);
			else
				ptd_put(pt, va);
		}
	}

	spin_unlock_irqrestore(&pt->lock, flags);
}

/*
 * map a section
 */
static int map_section(struct pt_struct *pt,
	unsigned long va, unsigned long val)
{
	int ret = -EFAULT;
	ptd_t *ptd = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);
	if (!ptd_null(ptd)) {
		ret = -EEXIST;
		goto out;
	}

	iowrite32(val, ptd);
	ret = 0;

out:
	spin_unlock_irqrestore(&pt->lock, flags);
	return ret;
}

/*
 * Unmap a section
 */
static void unmap_section(struct pt_struct *pt, unsigned long va)
{
	ptd_t *ptd = NULL;
	unsigned long flags = 0, size = 0;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);
	if (ptd_type_sect(ptd)) {
		iowrite32(0, ptd);
		flush_tlb_asid(pt->asid);
	} else if (ptd_type_page(ptd)) {
		spin_unlock_irqrestore(&pt->lock, flags);
		size = SECTION_SIZE;
		while (size) {
			unmap_page(pt, va);
			va += PAGE_SIZE;
			size -= PAGE_SIZE;
		}
		spin_lock_irqsave(&pt->lock, flags);
	}

	spin_unlock_irqrestore(&pt->lock, flags);
}

static void map_setzero(struct pt_struct *pt,
	void *va, unsigned long pteval)
{
	if (kpt() == pt)
		memset(va, 0, PAGE_SIZE);
	else if (pt == current->proc->pt)
		memset(va, 0, PAGE_SIZE);
	else {
		va = phys_to_virt(pteval & PAGE_MASK);
		memset(va, 0, PAGE_SIZE);
	}
}

static void map_section_setzero(struct pt_struct *pt,
	void *va, unsigned long secval)
{
	if (kpt() == pt)
		memset(va, 0, SECTION_SIZE);
	else if (pt == current->proc->pt)
		memset(va, 0, SECTION_SIZE);
	else {
		va = phys_to_virt(secval & SECTION_MASK);
		memset(va, 0, SECTION_SIZE);
	}
}

int map(struct pt_struct *pt, unsigned long pa, void *_va,
	unsigned long size, unsigned long flags)
{
	int ret = -ENOMEM, is_kern = (pt->asid == 0);
	unsigned long va = (unsigned long)_va, va_start = va;
	unsigned long secval = 0, pteval = 0, ptdflag = 0;
	unsigned long cache = 0, ap = 0, ns = 0;

	if ((!va) || (!pa))
		return -EINVAL;

	if ((va & (~PAGE_MASK)) || (pa & (~PAGE_MASK))) {
		EMSG("pa/va isn't page-aligned\n");
		return -EINVAL;
	}

	if ((flags & PG_ZERO) && !(flags & PG_RW)) {
		EMSG("PG_ZERO must with PG_RW\n");
		return -EINVAL;
	}

	if (size == 0)
		return 0;

	if (size & (~PAGE_MASK)) {
		EMSG("size isn't page-aligned %lx\n", size);
		return -EINVAL;
	}

	cache = (flags & PG_DMA) ? 0 : 1;
	ns = (mem_in_secure(pa) || !cache) ? 0 : 1;

	switch (flags & PG_RW) {
	case PG_RO:
		ap = (is_kern) ? KERN_RO_USER_NO : KERN_RO_USER_RO;
		break;
	case PG_RW:
		ap = (is_kern) ? KERN_RW_USER_NO : KERN_RW_USER_RW;
		break;
	default:
		return -EINVAL;
	}

	while (size) {
		if (is_kern == user_addr(va)) {
			ret = -EACCES;
			goto out;
		}

		if ((size < SECTION_SIZE) ||
			(va & (SECTION_SIZE - 1)) ||
			(pa & (SECTION_SIZE - 1))) {
			if ((ptdflag & MMU_TYPE_PAGE) == 0) {
				ptdflag |= MMU_TYPE_PAGE;
				ptdflag |= (is_kern ? MMU_KERN_DOMAIN :
						MMU_USER_DOMAIN) << MMU_L1_DOM_SHIFT;
				ptdflag |= ns << MMU_L1_NS_SHIFT;
			}

			pteval &= ~PAGE_MASK;
			pteval |= pa;
			if ((pteval & MMU_PAGE_TYPE_SMALL) == 0) {
				pteval |= MMU_PAGE_TYPE_SMALL;
				pteval |= cache << MMU_L2_B_SHIFT;
				pteval |= cache << MMU_L2_C_SHIFT;
				pteval |= cache << MMU_L2_TEX_SHIFT;
				pteval |= ((flags & PG_EXEC) ? 0 : 1) << MMU_L2_XN_SHIFT;
				pteval |= (ap & MMU_AP_MASK) << MMU_L2_AP_SHIFT;
				pteval |= (ap >> 2) << MMU_L2_AP2_SHIFT;
				pteval |= cache << MMU_L2_S_SHIFT;

				/*
				 * The not global bit. If a lookup using this descriptor is
				 * cached in a TLB, determines whether the TLB entry applies
				 * to all ASID values, or only to the current ASID value
				 */
				pteval |= (is_kern ? 0 : 1) << MMU_L2_NG_SHIFT;
			}

			ret = map_page(pt, va, ptdflag, pteval);
			if (ret)
				goto out;

			if (flags & PG_ZERO)
				map_setzero(pt, (void *)va, pteval);

			va += PAGE_SIZE;
			pa += PAGE_SIZE;
			size -= PAGE_SIZE;
		} else {
			secval &= ~SECTION_MASK;
			secval |= pa;
			if ((secval & MMU_TYPE_SECTION) == 0) {
				secval |= MMU_TYPE_SECTION;
				secval |= cache << MMU_SECTION_B_SHIFT;
				secval |= cache << MMU_SECTION_C_SHIFT;
				secval |= cache << MMU_SECTION_TEX_SHIFT;
				secval |= ((flags & PG_EXEC) ? 0 : 1) << MMU_SECTION_XN_SHIFT;
				secval |= (ap & MMU_AP_MASK) << MMU_SECTION_AP_SHIFT;
				secval |= (ap >> 2) << MMU_SECTION_AP2_SHIFT;
				secval |= cache << MMU_SECTION_S_SHIFT;
				secval |= (is_kern ? 0 : 1) << MMU_SECTION_NG_SHIFT;
				secval |= MMU_KERN_DOMAIN << MMU_SECTION_DOM_SHIFT;
				secval |= ns << MMU_SECTION_NS_SHIFT;
			}

			ret = map_section(pt, va, secval);
			if (ret)
				goto out;

			if (flags & PG_ZERO)
				map_section_setzero(pt, (void *)va, secval);

			va += SECTION_SIZE;
			pa += SECTION_SIZE;
			size -= SECTION_SIZE;
		}
	}

out:
	if (ret)
		unmap(pt, (void *)va_start, va - va_start);
	return ret;
}

void unmap(struct pt_struct *pt, void *_va, unsigned long size)
{
	unsigned long va = (unsigned long)_va;

	if (!va || !size)
		return;

	if ((va & (~PAGE_MASK)) || (size & (~PAGE_MASK))) {
		EMSG("va/size isn't page-aligned\n");
		return;
	}

	while (size) {
		if ((size < SECTION_SIZE) ||
			(va & (~SECTION_MASK))) {
			unmap_page(pt, va);
			va += PAGE_SIZE;
			size -= PAGE_SIZE;
		} else {
			unmap_section(pt, va);
			va += SECTION_SIZE;
			size -= SECTION_SIZE;
		}
	}
}

/* release resource from specified pt */
static void unmap_cleanup(struct pt_struct *pt)
{
	ptd_t *ptd = pt->ptds;
	size_t nr = PTDS_PER_PT;

	do {
		if (!ptd_null(ptd) && ptd_type_page(ptd))
			ptd_free(ptd);
		ptd++;
	} while (--nr);
}

unsigned long user_virt_to_phys(void *_va)
{
	unsigned long flags = 0;
	unsigned long pa = 0, va = (long)_va;

	local_irq_save(flags);

	/* ATS1CUR, Stage 1 current state unprivileged (PL0) read. */
	asm volatile("mcr p15, 0, %0, c7, c8, 2\n"
				"isb\n"
				:
				: "r"(va)
				: "memory", "cc");

	asm volatile("mrc p15, 0, %0, c7, c4, 0\n"
				: "=r" (pa)
				:
				: "memory", "cc");

	local_irq_restore(flags);

	pa &= PAGE_MASK;
	return pa ? (pa | (va &	(~PAGE_MASK))) : 0;
}

unsigned long user_virt_to_phys_pt(
	struct pt_struct *pt, void *_va)
{
	ptd_t *ptd = NULL;
	pte_t *pte = NULL;
	unsigned long pa = 0, va = (long)_va;
	unsigned long flags = 0;

	local_irq_save(flags);
	ptd = ptd_of(pt, va);
	if (!ptd_null(ptd)) {
		pte = pte_of(ptd, va);
		pa = pte->val & PAGE_MASK;
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
	unsigned long val = 0;
	unsigned long va = (unsigned long)addr;

	while (checked < size) {
		ptd = ptd_of(pt, va + checked);

		if (ptd_type_page(ptd)) {
			pte = pte_of(ptd, va + checked);
			val = pte->val;
			if (!val || ((prot == PG_RW) &&	(((val >> MMU_L2_AP_SHIFT)
				& MMU_AP_MASK) != KERN_RW_USER_RW)))
				return false;

			checked += PAGE_SIZE;
		} else if (ptd_type_sect(ptd)) {
			val = ptd->flags;

			if ((prot == PG_RW) &&	(((val >> MMU_SECTION_AP_SHIFT)
				& MMU_AP_MASK) != (user_addr(va + checked)
					? KERN_RW_USER_RW : KERN_RW_USER_NO)))
				return false;

			checked += SECTION_SIZE;
		} else
			return false;
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
	if (ASID_VALID(pt->asid)) {
		flush_tlb_asid(pt->asid);
		ida_free(&asida, pt->asid);
	}
}

/* allocate page table base entry for user process */
int alloc_pt(struct process *proc)
{
	void *ptd = 0;
	struct pt_struct *pt = NULL;

	pt = kmalloc(sizeof(struct pt_struct));
	if (pt == NULL)
		return -ENOMEM;

	spin_lock_init(&pt->lock);

	ptd = pages_alloc_continuous(PG_RW | PG_ZERO,
				PT_SIZE >> PAGE_SHIFT);
	if (ptd == NULL)
		goto err;

	alloc_asid(pt);

	pt->ptds = ptd;
	pt->refc = NULL;
	pt->proc = proc;
	proc->pt = pt;

	return 0;

err:
	pages_free_continuous(ptd);
	kfree(pt);
	return -ENOMEM;
}

void free_pt(struct pt_struct *pt)
{
	if (pt && pt != kpt()) {
		unmap_cleanup(pt);
		free_asid(pt);
		pages_free_continuous(pt->ptds);
		kfree(pt->refc);
		kfree(pt);
	}
}

unsigned long mmu_section_size(void)
{
	return SECTION_SIZE;
}

int __init map_early(unsigned long pa,	size_t size, unsigned long flags)
{
	struct pt_struct earlypt = {
		.ptds = __kern_early_pgtbl,
		.refc = NULL, .asid = 0,
		.lock = SPIN_LOCK_INIT(0)};
	int ret = -1, is_kern = true;
	unsigned long secval = 0;
	unsigned long cache = 1, ap = 0, ns = 0;

	switch (flags & PG_RW) {
	case PG_RO:
		ap = (is_kern) ? KERN_RO_USER_NO : KERN_RO_USER_RO;
		break;
	case PG_RW:
		ap = (is_kern) ? KERN_RW_USER_NO : KERN_RW_USER_RW;
		break;
	default:
		return -EINVAL;
	}

	if (((pa & (~SECTION_MASK)) +
		(size & (~SECTION_MASK))) > SECTION_SIZE)
		size += SECTION_SIZE;

	pa &= SECTION_MASK;

	while (size) {
		secval &= ~SECTION_MASK;
		secval |= pa;
		if ((secval & MMU_TYPE_SECTION) == 0) {
			secval |= MMU_TYPE_SECTION;
			secval |= cache << MMU_SECTION_B_SHIFT;
			secval |= cache << MMU_SECTION_C_SHIFT;
			secval |= cache << MMU_SECTION_TEX_SHIFT;
			secval |= ((flags & PG_EXEC) ? 0 : 1) << MMU_SECTION_XN_SHIFT;
			secval |= (ap & MMU_AP_MASK) << MMU_SECTION_AP_SHIFT;
			secval |= (ap >> 2) << MMU_SECTION_AP2_SHIFT;
			secval |= cache << MMU_SECTION_S_SHIFT;
			/*
			 * The not global bit. If a lookup using this descriptor is
			 * cached in a TLB, determines whether the TLB entry applies
			 * to all ASID values, or only to the current ASID value
			 */
			secval |= 1 << MMU_SECTION_NG_SHIFT; /* early mapping is nG */
			secval |= MMU_KERN_DOMAIN << MMU_SECTION_DOM_SHIFT;
			secval |= ns << MMU_SECTION_NS_SHIFT;
		}

		ret = map_section(&earlypt, (unsigned long)phys_to_virt(pa), secval);
		if (ret && (ret != -EEXIST))
			return ret;

		pa += SECTION_SIZE;
		size -= min(size, (size_t)SECTION_SIZE);
	}

	return 0;
}

void __init mmu_init_kpt(struct pt_struct *pt)
{
	/* the leading 4K is reserved, because kern only map the higher 3GB */
	pt->ptds = __kern_pgtbl;
	/* refc need 4K space, borrow from __kern_ptd (the reserved leading 4K) */
	pt->refc = __kern_pgtbl;
	pt->lock = SPIN_LOCK_INIT(0);
	pt->proc = kproc();
	pt->asid = 0;
}

void __init mmu_init(void)
{
	/* only called from CPU-0 */
	/* only called from CPU-0 */

	BUILD_ERROR_ON(VA_OFFSET < USER_VA_TOP);

	init_asid();

	mmu_set_ttbr0(0);
	mmu_set_ttbr1(MMU_TTBR(kpt()));

	/* client type */
	mmu_set_domain(MMU_KERN_DOMAIN, MMU_DOMAIN_CLIENT);
	mmu_set_domain(MMU_USER_DOMAIN, MMU_DOMAIN_CLIENT);

	mmu_divide_space();

	mmu_enable();

	/*
	 * early pgtbl maps the .text with PG_RW|PG_EXEC @ ASID 0, so
	 * here need to clean the old TLBs with ASID 0 or all local TLBs,
	 * to make the new flags PG_RO|PG_EXEC in use ASAP.
	 */
	local_flush_tlb_all();
	flush_icache_all();
}
