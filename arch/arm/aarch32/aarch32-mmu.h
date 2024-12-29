/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MMU Private Definitions for AArch32@ARMV7-A PageTable/TLB Handing
 */

#ifndef _MMUPRIV_H
#define _MMUPRIV_H

#include <defs.h>
#include <page.h>

/*
 * HW ASID is 8-bit width
 * 1 ~ 254, 0 / 255 are reserved
 */
#define ASID_START (1)
#define ASID_END (255)
#define ASID_VALID(_x_)		\
		(((_x_) >= ASID_START) && ((_x_) < ASID_END))
#define ASID_MASK (ASID_END)

#define ASID_RESVD (ASID_END)

/*
 * User Space VA space = (1UL << (32 - TTBCR_VAL))
 * 1GB for per User-App, 3GB for kernel
 * TTBR0 for User-App, TTBR1 for kernel
 *
 * Page 1327: Selecting between TTBR0 and TTBR1,
 * Short-descriptor translation table format
 */
#define MMU_TTBCR_VAL (2)

#define MMU_DOMAIN_CLIENT	1 /* Memory Type - Client */
#define MMU_KERN_DOMAIN		0
#define MMU_USER_DOMAIN		1

/*
 * access permission flags
 */
#define KERN_RW_USER_NO (1)
#define KERN_RW_USER_RW (3)
#define KERN_RO_USER_NO (5)
#define KERN_RO_USER_RO (7)

#define MMU_AP_MASK					(3)

#define MMU_TYPE_FAULT				(0)
#define MMU_TYPE_PAGE				(1)
#define MMU_TYPE_SECTION			(2)
#define MMU_TYPE_MASK				(3)

#define MMU_PAGE_TYPE_SMALL			(2)

/*
 * c/b/dom bit shift are same
 * for section/page mappings
 */
#define MMU_SECTION_B_SHIFT			(2)
#define MMU_SECTION_C_SHIFT			(3)
#define MMU_SECTION_XN_SHIFT		(4)
#define MMU_SECTION_DOM_SHIFT		(5)
#define MMU_SECTION_AP_SHIFT		(10)
#define MMU_SECTION_TEX_SHIFT		(12)
#define MMU_SECTION_AP2_SHIFT		(15)
#define MMU_SECTION_S_SHIFT			(16)
#define MMU_SECTION_NG_SHIFT		(17)
#define MMU_SECTION_NS_SHIFT		(19)
#define SECTION_MAP_FLAGS (MMU_TYPE_SECTION | (UL(1) << MMU_SECTION_B_SHIFT) | \
	(UL(1) << MMU_SECTION_C_SHIFT) | (UL(1) << MMU_SECTION_TEX_SHIFT) | \
	(UL(1) << MMU_SECTION_AP_SHIFT) | (UL(1) << MMU_SECTION_S_SHIFT) | \
	(UL(1) << MMU_SECTION_NG_SHIFT))

/*
 * NS bit only exists in the L1
 */
#define MMU_L1_NS_SHIFT				(3)
#define MMU_L1_DOM_SHIFT			(5)

#define MMU_L2_XN_SHIFT				(0)
#define MMU_L2_B_SHIFT				(2)
#define MMU_L2_C_SHIFT				(3)
#define MMU_L2_AP_SHIFT				(4)
#define MMU_L2_TEX_SHIFT			(6)
#define MMU_L2_AP2_SHIFT			(9)
#define MMU_L2_S_SHIFT				(10)
#define MMU_L2_NG_SHIFT				(11)

#define PTD_SHIFT		(20)
#define PTDS_PER_PT		(UL(4096) >> MMU_TTBCR_VAL)
#define PTE_SHIFT		(8)
#define PTES_PER_PTD	(UL(1) << PTE_SHIFT)

#define PTDS_PER_KPT	(UL(4096))

/*
 * section size
 */
#define SECTION_SHIFT	(PTD_SHIFT)
#define SECTION_SIZE	(UL(1) << SECTION_SHIFT)
#define SECTION_MASK	(~(SECTION_SIZE - 1))

/*
 * MMU on/off with cache/bp/wxn attributes
 */
#define	SCTLR_MMU_BIT			(UL(1) << 0)
#define SCTLR_DCACHE_BIT		(UL(1) << 2)
#define SCTLR_BRANCH_PRED_BIT	(UL(1) << 11)
#define SCTLR_ICACHE_BIT		(UL(1) << 12)
#define SCTLR_WXN_BIT			(UL(1) << 19)
#define MMU_ENABLE_FLAGS	(SCTLR_MMU_BIT | SCTLR_ICACHE_BIT | \
	SCTLR_DCACHE_BIT | SCTLR_BRANCH_PRED_BIT | SCTLR_WXN_BIT)

/*
 * NOS, bit[5] Not Outer Shareable bit. 1 Inner Shareable.
 * IRGN, bits[0, 6] = 0b01 -- Inner Write-Back Write-Allocate Cacheable
 * RGN, bits[4:3] = 0b01 -- Outer Write-Back Write-Allocate Cacheable
 * S, bit[1] = 1 -- Shareable
 */
#define MMU_TTBR_FLAGS ((UL(1) << 6) | (UL(0) << 5) | (UL(1) << 3) | (UL(1) << 1))

/*
 * Get the phys TranslationTableBase with arch-specific flags
 */
#define MMU_TTBR(pt) (virt_to_phys((pt)->ptds) | MMU_TTBR_FLAGS)

#ifndef __ASSEMBLY__

#include <cpu.h>
#include <trace.h>
#include <cache.h>
#include <kmalloc.h>
#include <stdbool.h>

extern unsigned long __kern_early_pgtbl[];

/*
 * Each PageTable contains #PTDS_PER_PT PageTableDirectory
 * Each PageTableDirectory contains 256 PageTableEntry
 */
typedef struct {unsigned long val; } pte_t;

/*
 * PTD pointer is aligned to PTD_SIZE
 */
typedef struct {
	/*
	 * flags of level 1
	 */
	unsigned long flags: PTE_SHIFT;

	/*
	 * Pointer address of this PTD
	 */
	unsigned long addr: BITS_PER_LONG - PTE_SHIFT;
} ptd_t;

#define PTD_SIZE		(PTES_PER_PTD * sizeof(pte_t))
#define PT_SIZE			(PTDS_PER_PT * sizeof(ptd_t))

#define ptd_index(x)	((x) >> PTD_SHIFT)
#define pte_index(x)	(((x) >> PAGE_SHIFT) & (PTES_PER_PTD - 1))

#define ptdp_of(pt)		((ptd_t *)(pt)->ptds)
#define ptep_of(ptd)	((pte_t *)phys_to_virt(((ptd)->addr) << PTE_SHIFT))

static inline ptd_t *ptd_of(struct pt_struct *pt, unsigned long va)
{
	return ptdp_of(pt) + ptd_index(va);
}

static inline int ptd_null(ptd_t *ptd)
{
	return !ptd->addr;
}

static inline void ptd_clear(ptd_t *ptd)
{
	ptd->addr = 0;
	ptd->flags = 0;
}

static inline void ptd_setflags(ptd_t *ptd, unsigned long flags)
{
	ptd->flags = flags;
}

static inline int ptd_alloc(ptd_t *ptd)
{
	void *ptep = kzalloc(PTD_SIZE);

	if (ptep == NULL)
		return -ENOMEM;

	ptd->addr = virt_to_phys(ptep) >> PTE_SHIFT;

	return 0;
}

static inline void ptd_free(ptd_t *ptd)
{
	kfree(ptep_of(ptd));
	ptd_clear(ptd);
}

static inline int ptd_type_sect(ptd_t *ptd)
{
	return (ptd->flags & MMU_TYPE_MASK) == MMU_TYPE_SECTION;
}

static inline int ptd_type_page(ptd_t *ptd)
{
	return (ptd->flags & MMU_TYPE_MASK) == MMU_TYPE_PAGE;
}

/*
 * return current reference counter
 */
static inline int ptd_refc(struct pt_struct *pt,
	unsigned long va)
{
	if (pt->refc)
		return *(unsigned char *)(pt->refc + ptd_index(va));

	return -1;
}

/*
 * increase reference counter
 */
static inline void ptd_hold(struct pt_struct *pt,
	unsigned long va)
{
	if (pt->refc)
		*(unsigned char *)(pt->refc + ptd_index(va)) += 1;
}

/*
 * Decrease reference counter
 */
static inline void ptd_put(struct pt_struct *pt,
	unsigned long va)
{
	if (pt->refc)
		*(unsigned char *)(pt->refc + ptd_index(va)) -= 1;
}

static inline pte_t *pte_of(ptd_t *ptd, unsigned long va)
{
	return ptep_of(ptd) + pte_index(va);
}

static inline void pte_set(pte_t *pte, unsigned long val)
{
	pte->val = val;
}

static inline int pte_null(pte_t *pte)
{
	return !pte->val;
}

static inline void mmu_set_domain(int domain, int access)
{
	unsigned long dacr = 0;
	unsigned long mask = ~(UL(3) << (domain * 2));

	asm volatile (
		"mrc p15, 0, %0, c3, c0, 0\n"
		: "=r" (dacr)
		:
		: "memory", "cc");

	dacr = (dacr & mask) | (access << (domain * 2));

	asm volatile (
		"mcr p15, 0, %0, c3, c0, 0\n"
		"isb\n"
		:
		: "r" (dacr)
		: "memory", "cc");
}

static inline void mmu_set_ttbr0(unsigned long ttbr0)
{
	asm volatile (
		"mcr p15, 0, %0, c2, c0, 0\n"
		"isb\n"
		:
		: "r" (ttbr0)
		: "memory", "cc");
}

static inline void mmu_set_ttbr1(unsigned long ttbr1)
{
	asm volatile (
		"mcr p15, 0, %0, c2, c0, 1\n"
		"isb\n"
		:
		: "r" (ttbr1)
		: "memory", "cc");
}

static inline void mmu_divide_space(void)
{
	unsigned long ttbcr = MMU_TTBCR_VAL;

	asm volatile (
		"mcr p15, 0, %0, c2, c0, 2\n"
		"isb\n"
		:
		: "r" (ttbcr)
		: "memory", "cc");
}

static inline void mmu_enable(void)
{
	unsigned long sctlr = 0;

	asm volatile ("dsb ishst\n"
		"mrc p15, 0, %0, c1, c0, 0\n"
		: "=r" (sctlr)
		:
		: "memory", "cc");

	sctlr |= MMU_ENABLE_FLAGS;

	asm volatile (
		"mcr p15, 0, %0, c1, c0, 0\n"
		"isb\n"
		:
		: "r" (sctlr)
		: "memory", "cc");
}

static inline void mmu_disable(void)
{
	unsigned long sctlr = 0;

	asm volatile ("dsb ishst\n"
		"mrc p15, 0, %0, c1, c0, 0\n"
		: "=r" (sctlr)
		:
		: "memory", "cc");

	sctlr &= ~SCTLR_MMU_BIT;

	asm volatile (
		"mcr p15, 0, %0, c1, c0, 0\n"
		"isb\n"
		:
		: "r" (sctlr)
		: "memory", "cc");
}

/*
 * invalidate all local TLB entries.
 */
static inline void local_flush_tlb_all(void)
{
	unsigned long xzrl = 0;

	asm volatile("dsb nshst\n"
				"mcr p15, 0, %0, c8, c7, 0\n"
				"dsb nsh\n"
				"isb\n"
				: : "r" (xzrl) : "memory", "cc");
}

/*
 * The flush_tlb_asid() invalidates
 * the TLB entries that matches the ASID value.
 */
static inline void flush_tlb_asid(unsigned long asid)
{
	/* Invalidate TLB by ASID (TLBIASIDIS) */
	asm volatile("dsb ishst\n"
				"mcr p15, 0, %0, c8, c3, 2\n"
				"dsb ish\n"
				"isb\n"
				:
				: "r" (asid)
				: "memory", "cc");
}

/*
 * The flush_tlb_pte() invalidates
 * a single TLB entry that matches the MVA
 * and (or ASID) values provided as an argument
 * to the function. (TLBIMVAIS)
 *
 * With global entries in the TLB, (kpt() pages)
 * the supplied ASID value is not checked.
 */
static inline void flush_tlb_pte(unsigned long mva,
	unsigned long asid)
{
	unsigned long va = mva | asid;

	asm volatile("dsb ishst\n"
		"mcr p15, 0, %0, c8, c3, 1\n"
		"dsb ish\n"
		"isb\n"
		:
		: "r" (va)
		: "memory", "cc");
}

#endif

#endif
