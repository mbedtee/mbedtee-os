// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MMU related functionalities for AArch64 based SoCs.
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
#include <cacheops.h>
#include <stdbool.h>
#include <sections.h>
#include <percpu.h>
#include <thread.h>
#include <kmalloc.h>
#include <uaccess.h>
#include <spinlock.h>

#include "aarch64-mmu.h"

/*
 * kernel page table for TTBR1
 * aligned to PAGE_SIZE
 */
unsigned long __kern_pgtbl[PTDS_PER_PT]
	__section(".bss")
	__aligned(PAGE_SIZE) = {0};

/* Process ASIDs */
static struct ida asida = {0};

static void __init init_asid(void)
{
	assert(ida_init(&asida, ASID_END) == 0);
	ida_set(&asida, 0);
}

static int map_page(struct pt_struct *pt,
	unsigned long va, unsigned long pteval)
{
	int ret = -ENOMEM;
	bool newptd = false, newpmd = false;
	ptd_t *ptd = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);
	if (ptd_null(ptd)) {
		ret = ptd_alloc(ptd);
		if (ret != 0)
			goto out;
		newptd = true;
		ptd_set_type_table(ptd);
	} else {
		if (!ptd_type_table(ptd)) {
			ret = -EFAULT;
			goto out;
		}
	}

	pmd = pmd_of(ptd, va);
	if (pmd_null(pmd)) {
		ret = pmd_alloc(pmd);
		if (ret != 0)
			goto out;
		if (newptd == false)
			ptd_hold(ptd);
		newpmd = true;
		pmd_set_type_table(pmd);
	} else {
		if (!pmd_type_table(pmd)) {
			ret = -EFAULT;
			goto out;
		}
	}

	pte = pte_of(pmd, va);
	if (pte_null(pte)) {
		if (newpmd == false)
			pmd_hold(pmd);
		pte_set(pte, pteval);
	} else {
		ret = -EEXIST;
		goto out;
	}

	ret = 0;

out:
	if ((ret != 0) && newptd)
		ptd_free(ptd);
	spin_unlock_irqrestore(&pt->lock, flags);
	return ret;
}

static void unmap_page(struct pt_struct *pt, unsigned long va)
{
	ptd_t *ptd = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);
	if (ptd_type_table(ptd)) {
		pmd = pmd_of(ptd, va);
		if (pmd_type_table(pmd)) {
			pte = pte_of(pmd, va);
			if (!pte_null(pte)) {
				pte_set(pte, 0);
				flush_tlb_pte(va, pt->asid);

				if (pmd_refc(pmd) == 0) {
					pmd_free(pmd);

					if (ptd_refc(ptd) == 0)
						ptd_free(ptd);
					else
						ptd_put(ptd);
				} else {
					pmd_put(pmd);
				}
			}
		}
	}

	spin_unlock_irqrestore(&pt->lock, flags);
}

static int map_section(struct pt_struct *pt,
	unsigned long va, unsigned long pmdval)
{
	int ret = -ENOMEM;
	ptd_t *ptd = NULL;
	pmd_t *pmd = NULL;
	int newptd = false;
	unsigned long flags = 0;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);
	if (ptd_null(ptd)) {
		ret = ptd_alloc(ptd);
		if (ret != 0)
			goto out;
		newptd = true;
		ptd_set_type_table(ptd);
	} else {
		if (!ptd_type_table(ptd)) {
			ret = -EFAULT;
			goto out;
		}
	}

	pmd = pmd_of(ptd, va);
	if (pmd_null(pmd)) {
		if (newptd == false)
			ptd_hold(ptd);
		pmd_set(pmd, pmdval);
	} else {
		ret = -EEXIST;
		goto out;
	}

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
	pmd_t *pmd = NULL;
	unsigned long flags = 0, size = 0;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);
	if (ptd_type_table(ptd)) {
		pmd = pmd_of(ptd, va);
		if (pmd_type_sect(pmd)) { /* SECT */
			pmd_set(pmd, 0);
			flush_tlb_asid(pt->asid);
			if (ptd_refc(ptd) == 0)
				ptd_free(ptd);
			else
				ptd_put(ptd);
		} else if (pmd_type_table(pmd)) { /* TABLE */
			spin_unlock_irqrestore(&pt->lock, flags);
			size = SECTION_SIZE;
			while (size) {
				unmap_page(pt, va);
				va += PAGE_SIZE;
				size -= PAGE_SIZE;
			}
			spin_lock_irqsave(&pt->lock, flags);
		} else
			panic("pmd %lx\n", pmd->val);
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
		va = phys_to_virt(pteval & (PAGE_MASK & PA_MASK));
		memset(va, 0, PAGE_SIZE);
	}
}

static void map_section_setzero(struct pt_struct *pt,
	void *va, unsigned long pmdval)
{
	if (kpt() == pt)
		memset(va, 0, SECTION_SIZE);
	else if (pt == current->proc->pt)
		memset(va, 0, SECTION_SIZE);
	else {
		va = phys_to_virt(pmdval & (SECTION_MASK & PA_MASK));
		memset(va, 0, SECTION_SIZE);
	}
}

int map(struct pt_struct *pt, unsigned long pa, void *_va,
	unsigned long size, unsigned long flags)
{
	int ret = -ENOMEM, is_kern = (pt->asid == 0);
	unsigned long va = (unsigned long)_va, va_start = va;
	unsigned long memtype = 0, ap = 0, ns = 0;
	unsigned long pteval = 0, pmdval = 0;

	if (!va)
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

	memtype = (flags & PG_DMA) ? MT_DEVICE_nGnRnE : MT_NORMAL;
	ns = (mem_in_secure(pa) || (flags & PG_DMA)) ? 0 : 1;

	while (size) {
		if (is_kern == user_addr(va)) {
			ret = -EACCES;
			goto out;
		}

		if ((size < SECTION_SIZE) ||
			(va & (SECTION_SIZE - 1)) ||
			(pa & (SECTION_SIZE - 1))) {
			pteval &= ~(PAGE_MASK & PA_MASK);
			pteval |= pa;
			if ((pteval & PTE_TYPE_MASK) == 0) {
				pteval |= PTE_TYPE_PAGE | PTE_SHARED | PTE_AF;
				pteval |= PTE_ATTRINDX(memtype) | ap;
				pteval |= ns ? PTE_NS : 0;
				pteval |= (flags & PG_EXEC) ? (is_kern ? PTE_UXN : PTE_PXN)
							: (PTE_PXN | PTE_UXN);
				/*
				 * The not global bit. If a lookup using this descriptor is
				 * cached in a TLB, determines whether the TLB entry applies
				 * to all ASID values, or only to the current ASID value
				 */
				pteval |= is_kern ? 0 : PTE_NG;
			}

			ret = map_page(pt, va, pteval);
			if (ret)
				goto out;

			if (flags & PG_ZERO)
				map_setzero(pt, (void *)va, pteval);
			va += PAGE_SIZE;
			pa += PAGE_SIZE;
			size -= PAGE_SIZE;
		} else {
			pmdval &= ~(SECTION_MASK & PA_MASK);
			pmdval |= pa;
			if ((pmdval & PMD_TYPE_MASK) == 0) {
				pmdval |= PMD_TYPE_SECT | PMD_SHARED | PMD_AF;
				pmdval |= PMD_ATTRINDX(memtype) | ap;
				pmdval |= ns ? PMD_NS : 0;
				pmdval |= (flags & PG_EXEC) ? (is_kern ? PMD_UXN : PMD_PXN)
							: (PMD_PXN | PMD_UXN);
				pmdval |= is_kern ? 0 : PMD_NG;
			}

			ret = map_section(pt, va, pmdval);
			if (ret)
				goto out;

			if (flags & PG_ZERO)
				map_section_setzero(pt, (void *)va, pmdval);

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
	ptd_t *ptd = NULL;
	pmd_t *pmd = NULL;
	size_t nr_pmd = 0;
	size_t nr_ptd = PTDS_PER_PT;

	ptd = ptd_of(pt, 0);
	do {
		if (!ptd_null(ptd)) {
			pmd = pmd_of(ptd, 0);
			nr_pmd = PMDS_PER_PTD;
			do {
				if (!pmd_null(pmd) && pmd_type_table(pmd))
					pmd_free(pmd);
				pmd++;
			} while (--nr_pmd);

			ptd_free(ptd);
		}
		ptd++;
	} while (--nr_ptd);
}

unsigned long user_virt_to_phys(void *_va)
{
	unsigned long flags = 0;
	unsigned long pa = 0, va = (long)_va;

	local_irq_save(flags);

	/* AT S1E0R, Address Translate Stage 1 EL0 Read */
	asm volatile("at s1e0r, %0\n"
				:
				: "r" (va)
				: "memory", "cc");

	asm volatile("isb\n"
				"mrs %0, par_el1\n"
				: "=r" (pa)
				:
				: "memory", "cc");

	local_irq_restore(flags);

	/* Translate Fault */
	if (pa & 1)
		return 0;

	pa &= (PAGE_MASK & PA_MASK);
	return pa ? (pa | (va &	(~PAGE_MASK))) : 0;
}

unsigned long user_virt_to_phys_pt(
	struct pt_struct *pt, void *_va)
{
	ptd_t *ptd = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	unsigned long pa = 0, va = (long)_va;
	unsigned long flags = 0;

	local_irq_save(flags);
	ptd = ptd_of(pt, va);
	if (!ptd_null(ptd)) {
		pmd = pmd_of(ptd, va);
		if (!pmd_null(pmd)) {
			pte = pte_of(pmd, va);
			pa = pte->val & (PAGE_MASK & PA_MASK);
		}
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
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	size_t checked = 0;
	unsigned long val = 0;
	unsigned long va = (unsigned long)addr;

	while (checked < size) {
		ptd = ptd_of(pt, va + checked);
		if (ptd_null(ptd))
			return false;

		pmd = pmd_of(ptd, va + checked);

		if (pmd_type_table(pmd)) {
			pte = pte_of(pmd, va + checked);
			val = pte->val;
			checked += PAGE_SIZE;
		} else if (pmd_type_sect(pmd)) {
			val = pmd->val;
			checked += SECTION_SIZE;
		} else
			return false;

		if (!val || ((prot == PG_RW) &&
			((val & PT_AP_MASK) != (user_addr(va + checked)
				? KERN_RW_USER_RW : KERN_RW_USER_NO))))
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
	void *ptd = NULL;
	struct pt_struct *pt = NULL;

	pt = kmalloc(sizeof(struct pt_struct));
	if (!pt)
		return -ENOMEM;

	spin_lock_init(&pt->lock);

	ptd = pages_alloc_continuous(PG_RW | PG_ZERO,
				PT_SIZE >> PAGE_SHIFT);
	if (!ptd)
		goto err;

	alloc_asid(pt);

	pt->ptds = ptd;
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
		kfree(pt);
	}
}

unsigned long mmu_section_size(void)
{
	return SECTION_SIZE;
}

int __init map_early(unsigned long pa,	size_t size, unsigned long flags)
{
#define NR_EARLY_PTDS 2
	struct pt_struct earlypt = {
		.ptds = __kern_early_pgtbl,
		.refc = NULL, .asid = 0,
		.lock = SPIN_LOCK_INIT(0)};
	int is_kern = true;
	unsigned long pmdval = 0, va = 0;
	unsigned long memtype = MT_NORMAL, ap = 0, ns = 0;
	ptd_t *ptd = NULL;
	pmd_t *pmd = NULL;
	static int idx;
	static char earlyptd[NR_EARLY_PTDS][PTD_SIZE]
		__section(".bss.early")
		__aligned(PTD_SIZE) = {0};

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
		pmdval &= ~(SECTION_MASK & PA_MASK);
		pmdval |= pa;
		if ((pmdval & PMD_TYPE_MASK) == 0) {
			pmdval |= PMD_TYPE_SECT | PMD_SHARED | PMD_AF;
			pmdval |= PMD_ATTRINDX(memtype) | ap;
			pmdval |= ns ? PMD_NS : 0;
			pmdval |= (flags & PG_EXEC) ? (is_kern ? PMD_UXN : PMD_PXN)
						: (PMD_PXN | PMD_UXN);
			/*
			 * The not global bit. If a lookup using this descriptor is
			 * cached in a TLB, determines whether the TLB entry applies
			 * to all ASID values, or only to the current ASID value
			 */
			pmdval |= PMD_NG; /* early mapping is nG, force to ASID 0 */
		}

		va = (unsigned long)phys_to_virt(pa);

		ptd = ptd_of(&earlypt, va);
		if (ptd_null(ptd)) {
			if (idx == NR_EARLY_PTDS)
				return 0;

			ptd_set(ptd, virt_to_phys(&earlyptd[idx++]));
			ptd_set_type_table(ptd);
		}

		pmd = pmd_of(ptd, va);
		if (pmd_null(pmd))
			pmd_set(pmd, pmdval);

		pa += SECTION_SIZE;
		size -= min(size, (size_t)SECTION_SIZE);
	}

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
	/* only called from CPU-0 */
	/* only called from CPU-0 */

	BUILD_ERROR_ON(VA_BITS != 39);
	BUILD_ERROR_ON(VA_OFFSET < USER_VA_TOP);

	init_asid();

	mmu_set_ttbr0(0);
	mmu_set_ttbr1(MMU_TTBR(kpt()));

	mmu_set_mair(MAIR_VAL);

	mmu_set_tcr(TCR_VAL);

	mmu_set_sctlr(SCTLR_VAL);

	/*
	 * early pgtbl maps the .text with PG_RW|PG_EXEC @ ASID 0, so
	 * here need to clean the old TLBs with ASID 0 or all local TLBs,
	 * to make the new flags PG_RO|PG_EXEC in use ASAP.
	 */
	local_flush_tlb_all();

	flush_icache_all();
}
