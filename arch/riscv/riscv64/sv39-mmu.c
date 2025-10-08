// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MMU related functionalities for Sv39 based SoCs.
 */

#include <io.h>
#include <mmu.h>
#include <init.h>
#include <list.h>
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

#include "riscv-mmu.h"

/*
 * kernel page table directories
 */
unsigned long __kern_pgtbl[PTDS_PER_PT]
	__section(".bss") __aligned(PAGE_SIZE) = {0};
/*
 * for kpt only, PMDs refc
 * PTD refs reuses the __kern_pgtbl.
 */
static unsigned short __kern_pgtbl_refc[PMDS_PER_PTD *
	(-KERN_VA_START >> PTD_SHIFT)] __section(".bss") = {0};

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
		ptd_setflags(ptd, PTD_VALID);
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
			ptd_hold(pt, va);
		newpmd = true;
		pmd_setflags(pmd, PMD_VALID);
	} else {
		if (!pmd_type_table(pmd)) {
			ret = -EFAULT;
			goto out;
		}
	}

	pte = pte_of(pmd, va);
	if (pte_null(pte)) {
		if (newpmd == false)
			pmd_hold(pt, va);
		pte_set(pte, pteval);
		/*
		 * in case of the current pt is an userspace proc pt
		 *
		 * for a kernel va, this va might be accessed soon,
		 * so sync its mapping from kpt() to current proc's pt
		 * to avoid triggering page_fault() exception.
		 */
		pt_sync(current->proc->pt, va);
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
	bool flushtlb = false, clearptd = false;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);
	if (!ptd_null(ptd)) {
		pmd = pmd_of(ptd, va);
		if (!pmd_null(pmd) && pmd_type_table(pmd)) {
			pte = pte_of(pmd, va);
			if (!pte_null(pte)) {
				pte_set(pte, 0);
				if (PROCESS_ALIVE(pt->proc))
					flushtlb = true;

				if (pmd_refc(pt, va) == 0) {
					pmd_free(pmd);
					if (ptd_refc(pt, va) == 0) {
						ptd_free(ptd);
						clearptd = true;
					} else
						ptd_put(pt, va);
				} else {
					pmd_put(pt, va);
				}
			}
		}
	}

	spin_unlock_irqrestore(&pt->lock, flags);

	if (flushtlb)
		flush_tlb_pte(va, pt->asid);
	if (clearptd)
		ptd_sync_clear(va);
}

/*
 * map a section
 */
static int map_section(struct pt_struct *pt,
	unsigned long va, unsigned long val)
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
		ptd_setflags(ptd, PTD_VALID);
	} else {
		if (!ptd_type_table(ptd)) {
			ret = -EFAULT;
			goto out;
		}
	}

	pmd = pmd_of(ptd, va);
	if (pmd_null(pmd)) {
		if (newptd == false)
			ptd_hold(pt, va);
		pmd_set(pmd, val);
		/*
		 * in case of the current pt is an userspace proc pt
		 *
		 * for a kernel va, this va might be accessed soon,
		 * so sync its mapping from kpt() to current proc's pt
		 * to avoid triggering page_fault() exception.
		 */
		pt_sync(current->proc->pt, va);
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
	bool flushtlb = false, clearptd = false;

	spin_lock_irqsave(&pt->lock, flags);

	ptd = ptd_of(pt, va);
	if (!ptd_null(ptd) && ptd_type_table(ptd)) {
		pmd = pmd_of(ptd, va);
		if (!pmd_type_table(pmd)) { /* SECT */
			pmd_set(pmd, 0);
			if (PROCESS_ALIVE(pt->proc))
				flushtlb = true;
			if (ptd_refc(pt, va) == 0) {
				ptd_free(ptd);
				clearptd = true;
			} else
				ptd_put(pt, va);
		} else if (!pmd_null(pmd)) { /* TABLE */
			spin_unlock_irqrestore(&pt->lock, flags);
			size = SECTION_SIZE;
			while (size) {
				unmap_page(pt, va);
				va += PAGE_SIZE;
				size -= PAGE_SIZE;
			}
			spin_lock_irqsave(&pt->lock, flags);
		} else {
			panic("pmd %lx\n", pmd->val);
		}
	}

	spin_unlock_irqrestore(&pt->lock, flags);

	if (flushtlb)
		flush_tlb_asid(pt->asid);
	if (clearptd)
		ptd_sync_clear(va);
}

static void map_setzero(struct pt_struct *pt,
	void *va, unsigned long pteval)
{
	if (kpt() == pt)
		memset(va, 0, PAGE_SIZE);
	else if (pt == current->proc->pt)
		memset(va, 0, PAGE_SIZE);
	else {
		va = phys_to_virt((pteval << PPN_BIAS) & PAGE_MASK & PA_MASK);
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
		va = phys_to_virt((secval << PPN_BIAS) & SECTION_MASK & PA_MASK);
		memset(va, 0, SECTION_SIZE);
	}
}

int map(struct pt_struct *pt, unsigned long pa, void *_va,
	unsigned long size, unsigned long flags)
{
	int ret = -ENOMEM, is_kern = (pt->asid == 0);
	unsigned long va = (unsigned long)_va, va_start = va;
	unsigned long secval = 0, pteval = 0;
	unsigned long rwx = PTE_READ;

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

	if ((flags & PG_RW) == PG_RW)
		rwx |= PTE_WRITE;

	if (flags & PG_EXEC)
		rwx |= PTE_EXECUTABLE;

	while (size) {
		if (is_kern == user_addr(va)) {
			ret = -EACCES;
			goto out;
		}

		if ((size < SECTION_SIZE) ||
			(va & (SECTION_SIZE - 1)) ||
			(pa & (SECTION_SIZE - 1))) {
			pteval &= ~((PAGE_MASK >> PPN_BIAS) & PA_MASK);
			pteval |= (pa >> PPN_BIAS);
			if ((pteval & PTE_VALID) == 0) {
				pteval |= rwx | PTE_VALID | PTE_ACCESSED | PTE_DIRTY;

				/*
				 * The global bit. If a lookup using this descriptor is
				 * cached in a TLB, determines whether the TLB entry applies
				 * to all ASID values, or only to the current ASID value
				 */
				pteval |= is_kern ? PTE_GLOBAL : 0;
				pteval |= is_kern ? 0 : PTE_USER;
			}

			ret = map_page(pt, pteval, va);
			if (ret)
				goto out;

			if (flags & PG_ZERO)
				map_setzero(pt, (void *)va, pteval);

			va += PAGE_SIZE;
			pa += PAGE_SIZE;
			size -= PAGE_SIZE;
		} else {
			secval &= ~((SECTION_MASK >> PPN_BIAS) & PA_MASK);
			secval |= (pa >> PPN_BIAS);
			if ((secval & PMD_VALID) == 0) {
				secval |= rwx | PMD_VALID | PMD_ACCESSED | PMD_DIRTY;

				/*
				 * The global bit. If a lookup using this descriptor is
				 * cached in a TLB, determines whether the TLB entry applies
				 * to all ASID values, or only to the current ASID value
				 */
				secval |= is_kern ? PMD_GLOBAL : 0;
				secval |= is_kern ? 0 : PMD_USER;
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

unsigned long user_virt_to_phys(void *va)
{
	return user_virt_to_phys_pt(current->proc->pt, va);
}

unsigned long user_virt_to_phys_pt(struct pt_struct *pt, void *_va)
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
			pa = (pte->val << PPN_BIAS) & (PAGE_MASK & PA_MASK);
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
		if (pmd_null(pmd))
			return false;

		if (pmd_type_table(pmd)) {
			pte = pte_of(pmd, va + checked);
			val = pte->val;
			checked += PAGE_SIZE;
		} else {
			val = pmd->val;
			checked += SECTION_SIZE;
		}

		if (!val || ((prot == PG_RW) &&
			!(val & PTE_WRITE)))
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

static inline int alloc_asid(struct pt_struct *pt)
{
	int asid = ida_alloc(&asida);

	if (asid <= 0) {
		DMSG("ASID not enough\n");
		asid = ASID_RESVD; /* reserved for emergency */
	}

	pt->asid = asid;
	return 0;
}

static inline void free_asid(struct pt_struct *pt)
{
	if (ASID_VALID(pt->asid)) {
		flush_tlb_asid(pt->asid);
		ida_free(&asida, pt->asid);
	}
}

/*
 * release resource from user process
 */
static void unmap_cleanup(struct pt_struct *pt)
{
	ptd_t *ptd = NULL;
	pmd_t *pmd = NULL;
	size_t nr_pmd = 0;
	size_t nr_ptd = USER_VA_TOP >> PTD_SHIFT;

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

/*
 * allocate page table for process
 */
int alloc_pt(struct process *proc)
{
	void *ptds = 0;
	struct pt_struct *pt = NULL;

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
	pt->refc = NULL;
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
#define NR_EARLY_PTDS 2
	struct pt_struct earlypt = {
		.ptds = __kern_early_pgtbl,
		.refc = NULL, .asid = 0,
		.lock = SPIN_LOCK_INIT(0)};
	int is_kern = true;
	unsigned long pmdval = 0, va = 0;
	ptd_t *ptd = NULL;
	pmd_t *pmd = NULL;
	unsigned long rwx = PTE_READ;
	static int idx;
	static char earlyptd[NR_EARLY_PTDS][PTD_SIZE]
		__section(".bss.early")
		__aligned(PTD_SIZE) = {0};

	if ((flags & PG_RW) == PG_RW)
		rwx |= PTE_WRITE;

	if (flags & PG_EXEC)
		rwx |= PTE_EXECUTABLE;

	if (((pa & (~SECTION_MASK)) +
		(size & (~SECTION_MASK))) > SECTION_SIZE)
		size += SECTION_SIZE;

	pa &= SECTION_MASK;

	while (size) {
		pmdval &= ~((SECTION_MASK >> PPN_BIAS) & PA_MASK);
		pmdval |= (pa >> PPN_BIAS);
		if ((pmdval & PMD_VALID) == 0) {
			pmdval |= rwx | PMD_VALID | PMD_ACCESSED | PMD_DIRTY;

			/*
			 * The global bit. If a lookup using this descriptor is
			 * cached in a TLB, determines whether the TLB entry applies
			 * to all ASID values, or only to the current ASID value
			 */
			pmdval |= is_kern ? 0 : 0; /* early mapping is nG */
			pmdval |= is_kern ? 0 : PMD_USER;
		}

		va = (unsigned long)phys_to_virt(pa);

		ptd = ptd_of(&earlypt, va);
		if (ptd_null(ptd)) {
			if (idx == NR_EARLY_PTDS)
				return 0;

			ptd_set(ptd, virt_to_phys(&earlyptd[idx++]) >> PPN_BIAS);
			ptd_setflags(ptd, PTD_VALID);
		}

		pmd = pmd_of(ptd, va);
		if (pmd_null(pmd))
			pmd_set(pmd, pmdval);

		local_flush_tlb_asid(0);

		pa += SECTION_SIZE;
		size -= min(size, (size_t)SECTION_SIZE);
	}

	return 0;
}

void __init mmu_init_kpt(struct pt_struct *pt)
{
	pt->ptds = __kern_pgtbl;
	pt->refc = __kern_pgtbl_refc;
	pt->lock = SPIN_LOCK_INIT(0);
	pt->proc = kproc();
	pt->asid = 0;
}

void __init mmu_init(void)
{
	/* only called from CPU-0 */
	/* only called from CPU-0 */

	init_asid();

	BUILD_ERROR_ON(VA_BITS != 39);
	BUILD_ERROR_ON(VA_OFFSET < USER_VA_TOP);

	mmu_enable(kpt());

	/*
	 * early pgtbl maps the .text with PG_RW|PG_EXEC @ ASID 0, so
	 * here need to clean the old TLBs with ASID 0 or all local TLBs,
	 * to make the new flags PG_RO|PG_EXEC in use ASAP.
	 */
	local_flush_tlb_all();

	flush_icache_all();
}
