/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MMU Private Definitions for AArch64 PageTable/TLB Handing
 */

#ifndef _MMUPRIV_H
#define _MMUPRIV_H

#include <defs.h>
#include <page.h>

/*
 * HW ASID is configured to 16-bit width
 * 1 ~ 510, 0 / 511 are reserved
 */
#define ASID_START (1)
#define ASID_END (511)
#define ASID_VALID(_x_)	\
		(((_x_) >= ASID_START) && ((_x_) < ASID_END))
#define ASID_MASK (ASID_END)
#define ASID_SHIFT (48)

#define ASID_RESVD (ASID_END)

/*
 * Each PageTable can map 512GB (39-bits AddressSpace, 4KB PageSize):
 * Each PageTable has 3 translation level, each level has 512 entries
 * Each PageTable contains 512 PageTableDirectory (PTD)
 * Each PageTableDirectory contains 512 PageTableMiddleDirectory (PMD)
 * Each PageTableMiddleDirectory contains 512 PageTableEntry (PTE)
 * ptd -> pmd -> pte
 *
 * Refer to D5.2.6-Overview of the VMSAv8-64 address translation stages
 */
#define PTE_SHIFT		((PAGE_SHIFT - 3) * 1 + 3) /* [20:12] */
#define PTES_PER_PMD	(UL(1) << (PAGE_SHIFT - 3))

#define PMD_SHIFT		((PAGE_SHIFT - 3) * 2 + 3) /* [29:21] */
#define PMDS_PER_PTD	(PTES_PER_PMD)

#define PTD_SHIFT		((PAGE_SHIFT - 3) * 3 + 3) /* [38:30] */
#define PTDS_PER_PT		(PTES_PER_PMD)

#define MT_NORMAL					0
#define MT_DEVICE_nGnRnE			1

#define MAIR_ATTR_DEVICE_nGnRnE		(UL(0x00))
#define MAIR_ATTR_NORMAL			(UL(0xff))

#define MAIR_VAL ((MAIR_ATTR_DEVICE_nGnRnE << 8) | MAIR_ATTR_NORMAL)

/*
 * PTE Attributes @ Page 2726
 * Attribute fields in stage 1 VMSAv8-64 Block and Page descriptors
 */
#define PTE_TYPE_MASK		(UL(3) << 0)
#define PTE_TYPE_PAGE		(UL(3) << 0)

#define PTE_ATTRINDX(t)		((t) << 2) /* idx in MAIR_EL* Memory Attribute Indirection Register */
#define PTE_ATTRINDX_MASK	(UL(7) << 2)
#define PTE_NS				(UL(1) << 5)  /* access the non-secure memory */
#define PTE_SHARED			(UL(2) << 8)  /* 0b11 - inner shareable. 0b10 - outer shareable */
#define PTE_AF				(UL(1) << 10) /* Access Flag */
#define PTE_NG				(UL(1) << 11) /* nG */

#define PTE_GP				(UL(1) << 50) /* BTI guarded */
#define PTE_DBM				(UL(1) << 51) /* Dirty Bit Management */
#define PTE_CONT			(UL(1) << 52) /* Contiguous range */
#define PTE_PXN				(UL(1) << 53) /* Privileged XN */
#define PTE_UXN				(UL(1) << 54) /* User XN */

/*
 * Reuse the IgnoreField as the refc of ptd/pmd table descriptors
 * PAGE SIZE 4KB,  512 entries	-> Bit [2:11] provide 1024
 * PAGE SIZE 16KB, 2048 entries -> Bit [2:13] provide 4096
 * PAGE SIZE 64KB, 8192 entries -> Bit [2:15] provide 16384
 */
#define REFC_SHIFT			(2)

/*
 * access permission flags @ PMD(Section)/PTE[7:6]
 */
#define KERN_RW_USER_NO  (UL(0) << 6)
#define KERN_RW_USER_RW  (UL(1) << 6)
#define KERN_RO_USER_NO  (UL(2) << 6)
#define KERN_RO_USER_RO  (UL(3) << 6)
#define PT_AP_MASK		 (UL(3) << 6)

/*
 * Level 2 descriptor (PMD).
 */
#define PMD_TYPE_MASK		(UL(3) << 0)
#define PMD_TYPE_TABLE		(UL(3) << 0)

/*
 * Refer to Page 2719:
	Descriptor encodings, Armv8 level 0, level 1, and level 2 formats
	Descriptor bit[0] identifies whether the descriptor is valid, and is 1 for a valid descriptor.
	If a lookup returns an invalid descriptor, the associated input address is unmapped,
	and any attempt to access it generates a Translation fault.

	Descriptor bit[1] identifies the descriptor type, and is encoded as:
	0, Block
		The descriptor gives the base address of a block of memory,
		and the attributes for that memory region.
	1, Table
		The descriptor gives the address of the next level of translation table,
		and for a stage 1 translation, some attributes for that translation
 */
#define PMD_TYPE_SECT		(UL(1) << 0)
#define PMD_ATTRINDX(t)		((t) << 2)
#define PMD_ATTRINDX_MASK	(UL(7) << 2)
#define PMD_NS				(UL(1) << 5)  /* access the non-secure memory */
#define PMD_SHARED			(UL(2) << 8)  /* 0b11 - inner shareable. 0b10 - outer shareable */
#define PMD_AF				(UL(1) << 10) /* Access Flag */
#define PMD_NG				(UL(1) << 11) /* nG */
#define PMD_PXN				(UL(1) << 53) /* Privileged XN */
#define PMD_UXN				(UL(1) << 54) /* User XN */

/*
 * section size
 */
#define SECTION_SHIFT	(PMD_SHIFT)
#define SECTION_SIZE	(UL(1) << SECTION_SHIFT)
#define SECTION_MASK	(~(SECTION_SIZE - 1))

#define SECTION_MAP_FLAGS (PMD_TYPE_SECT | PMD_NG | \
	PMD_SHARED | PMD_AF | PMD_ATTRINDX(MT_NORMAL))

#define PTD_TYPE_MASK		(UL(3) << 0)
#define PTD_TYPE_TABLE		(UL(3) << 0)

#define TCR_ASID16			(UL(1) << 36) /* ASID16 or ASID8 */

#define TCR_IPS_SHIFT		32
#define TCR_IPS_4G			(UL(0) << TCR_IPS_SHIFT)
#define TCR_IPS_64G			(UL(1) << TCR_IPS_SHIFT)
#define TCR_IPS_1T			(UL(2) << TCR_IPS_SHIFT)
#define TCR_IPS_4T			(UL(3) << TCR_IPS_SHIFT)
#define TCR_IPS_16T			(UL(4) << TCR_IPS_SHIFT)
#define TCR_IPS_256T		(UL(5) << TCR_IPS_SHIFT)
#define TCR_IPS_4P			(UL(6) << TCR_IPS_SHIFT)

#define TCR_TG1_SHIFT		30
#define TCR_TG1_16K			(UL(1) << TCR_TG1_SHIFT)
#define TCR_TG1_4K			(UL(2) << TCR_TG1_SHIFT) /* fixed to 4KB */
#define TCR_TG1_64K			(UL(3) << TCR_TG1_SHIFT)

#define TCR_SH1_SHIFT		28
#define TCR_SH1_OUTER		(UL(2) << TCR_SH1_SHIFT)
#define TCR_SH1_INNER		(UL(3) << TCR_SH1_SHIFT)

#define TCR_ORGN1_SHIFT		26
#define TCR_ORGN1_WBWA		(UL(1) << TCR_ORGN1_SHIFT) /* fixed to write-back write-allocate */
#define TCR_ORGN1_WT		(UL(2) << TCR_ORGN1_SHIFT)
#define TCR_ORGN1_WBnWA		(UL(3) << TCR_ORGN1_SHIFT)

#define TCR_IRGN1_SHIFT		24
#define TCR_IRGN1_WBWA		(UL(1) << TCR_IRGN1_SHIFT) /* fixed to write-back write-allocate */
#define TCR_IRGN1_WT		(UL(2) << TCR_IRGN1_SHIFT)
#define TCR_IRGN1_WBnWA		(UL(3) << TCR_IRGN1_SHIFT)

#define TCR_EPD1_SHIFT		23 /* TTBR1 walk disable */

#define TCR_A1				(UL(1) << 22) /* TTBR1 defines the ASID */

#define TCR_T1SZ(x)			((UL(64) - (x)) << 16)

#define TCR_TG0_SHIFT		14
#define TCR_TG0_4K			(UL(0) << TCR_TG0_SHIFT) /* fixed to 4KB */
#define TCR_TG0_64K			(UL(1) << TCR_TG0_SHIFT)
#define TCR_TG0_16K			(UL(2) << TCR_TG0_SHIFT)

#define TCR_SH0_SHIFT		12
#define TCR_SH0_OUTER		(UL(2) << TCR_SH0_SHIFT)
#define TCR_SH0_INNER		(UL(3) << TCR_SH0_SHIFT)

#define TCR_ORGN0_SHIFT		10
#define TCR_ORGN0_WBWA		(UL(1) << TCR_ORGN0_SHIFT) /* fixed to write-back write-allocate */
#define TCR_ORGN0_WT		(UL(2) << TCR_ORGN0_SHIFT)
#define TCR_ORGN0_WBnWA		(UL(3) << TCR_ORGN0_SHIFT)

#define TCR_IRGN0_SHIFT		8
#define TCR_IRGN0_WBWA		(UL(1) << TCR_IRGN0_SHIFT) /* fixed to write-back write-allocate */
#define TCR_IRGN0_WT		(UL(2) << TCR_IRGN0_SHIFT)
#define TCR_IRGN0_WBnWA		(UL(3) << TCR_IRGN0_SHIFT)

#define TCR_EPD0_SHIFT		7  /* TTBR0 walk disable */
#define TCR_T0SZ(x)			((UL(64) - (x)) << 0)

#define TCR_VAL (TCR_T0SZ(VA_BITS) | TCR_IRGN0_WBWA | TCR_ORGN0_WBWA  | \
	TCR_SH0_OUTER | TCR_TG0_4K | TCR_T1SZ(VA_BITS) | TCR_IRGN1_WBWA | \
	TCR_ORGN1_WBWA | TCR_SH1_OUTER | TCR_TG1_4K | TCR_IPS_1T | TCR_ASID16)

#define TCR_VAL_EL3 (TCR_T0SZ(VA_BITS) | TCR_IRGN0_WBWA | TCR_ORGN0_WBWA  | \
	TCR_SH0_OUTER | TCR_TG0_4K | (UL(2) << 16) | TCR_ASID16)

#define SCTLR_EPAN			(UL(1) << 57)
#define SCTLR_ATA			(UL(1) << 43)
#define SCTLR_ATA0			(UL(1) << 42)
#define SCTLR_ENIA			(UL(1) << 31) /* for FEAT_PAuth */
#define SCTLR_ENIB			(UL(1) << 30) /* for FEAT_PAuth */
#define SCTLR_LSMAOE		(UL(1) << 29)
#define SCTLR_NTLSMD		(UL(1) << 28)
#define SCTLR_ENDA			(UL(1) << 27)
#define SCTLR_UCI			(UL(1) << 26)
#define SCTLR_SPAN			(UL(1) << 23)
#define SCTLR_EIS			(UL(1) << 22)
#define SCTLR_IESB			(UL(1) << 21)
#define SCTLR_TSCXT			(UL(1) << 20)
#define SCTLR_WXN			(UL(1) << 19)
#define SCTLR_NTWE			(UL(1) << 18)
#define SCTLR_NTWI			(UL(1) << 16)
#define SCTLR_UCT			(UL(1) << 15)
#define SCTLR_DZE			(UL(1) << 14)
#define SCTLR_ENDB			(UL(1) << 13) /* for FEAT_PAuth */
#define SCTLR_I				(UL(1) << 12)
#define SCTLR_EOS			(UL(1) << 11)
#define SCTLR_ENRCTX		(UL(1) << 10)
#define SCTLR_UMA			(UL(1) << 9)
#define SCTLR_SED			(UL(1) << 8) /* EL0 aarch32 can use SETEND instruction */
#define SCTLR_ITD			(UL(1) << 7) /* EL0 aarch32 can use IT instruction */
#define SCTLR_NAA			(UL(1) << 6)
#define SCTLR_CP15BEN		(UL(1) << 5)
#define SCTLR_SA0			(UL(1) << 4)
#define SCTLR_SA			(UL(1) << 3)
#define SCTLR_C				(UL(1) << 2)
#define SCTLR_A				(UL(1) << 1)
#define SCTLR_M				(UL(1) << 0)

#define SCTLR_VAL (SCTLR_M | SCTLR_C | SCTLR_NAA | SCTLR_ITD | \
	 SCTLR_SED | SCTLR_EOS | SCTLR_I | SCTLR_DZE | SCTLR_WXN | \
	 SCTLR_EIS | SCTLR_SPAN | SCTLR_NTLSMD | SCTLR_LSMAOE | \
	 SCTLR_ATA0 | SCTLR_ATA | SCTLR_EPAN)

#define SCTLR_VAL_EL3 (SCTLR_M | SCTLR_C | SCTLR_NAA | SCTLR_EOS | \
	SCTLR_I | SCTLR_EIS)

/*
 * Get the phys TranslationTableBase with arch-specific flags
 */
#define MMU_TTBR(pt) ((((long)((pt)->asid)) << ASID_SHIFT) | \
				virt_to_phys((pt)->ptds))

#ifndef __ASSEMBLY__

#include <cpu.h>
#include <map.h>
#include <trace.h>
#include <cache.h>
#include <page.h>
#include <kmalloc.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

extern unsigned long __kern_early_pgtbl[];

typedef struct {unsigned long val; } pte_t;
typedef struct {unsigned long val; } pmd_t;
typedef struct {unsigned long val; } ptd_t;

#define PMD_SIZE		((unsigned long)PTES_PER_PMD * sizeof(pte_t))
#define PTD_SIZE		((unsigned long)PMDS_PER_PTD * sizeof(pmd_t))
#define PT_SIZE			((unsigned long)PTDS_PER_PT * sizeof(ptd_t))

#define ptd_index(x)	(((x) >> PTD_SHIFT) & (PTDS_PER_PT - 1))
#define pmd_index(x)	(((x) >> PMD_SHIFT) & (PMDS_PER_PTD - 1))
#define pte_index(x)	(((x) >> PAGE_SHIFT) & (PTES_PER_PMD - 1))

#define ptdp_of(pt)		((ptd_t *)(pt)->ptds)
#define pmdp_of(ptd)	((pmd_t *)phys_to_virt(((ptd)->val) & \
		((unsigned long)(~(PTD_SIZE - 1)))))
#define ptep_of(pmd)	((pte_t *)phys_to_virt(((pmd)->val) & \
		((unsigned long)(~(PMD_SIZE - 1)))))

static inline ptd_t *ptd_of(struct pt_struct *pt, unsigned long va)
{
	return ptdp_of(pt) + ptd_index(va);
}

static inline int ptd_null(ptd_t *ptd)
{
	return !ptd->val;
}

static inline void ptd_set(ptd_t *ptd, unsigned long val)
{
	ptd->val = val;
}

static inline int ptd_alloc(ptd_t *ptd)
{
	void *pmdp = kzalloc(PTD_SIZE);

	if (pmdp == NULL)
		return -ENOMEM;

	/* link the ptd with its sub-level -> PMD array */
	ptd_set(ptd, virt_to_phys(pmdp));
	return 0;
}

static inline void ptd_free(ptd_t *ptd)
{
	/* unlink the ptd with its sub-level -> PMD array */
	kfree(pmdp_of(ptd));
	ptd_set(ptd, 0);
}

/*
 * return current reference counter
 */
static inline int ptd_refc(ptd_t *ptd)
{
	return (ptd->val >> REFC_SHIFT) & (PMDS_PER_PTD - 1);
}

/*
 * increase reference counter
 */
static inline void ptd_hold(ptd_t *ptd)
{
	ptd->val += (UL(1) << REFC_SHIFT);
}

/*
 * Decrease reference counter
 */
static inline void ptd_put(ptd_t *ptd)
{
	ptd->val -= (UL(1) << REFC_SHIFT);
}

static inline int ptd_type_table(ptd_t *ptd)
{
	return (ptd->val & PTD_TYPE_MASK) == PTD_TYPE_TABLE;
}

static inline void ptd_set_type_table(ptd_t *ptd)
{
	ptd->val |= PTD_TYPE_TABLE;
}

static inline pmd_t *pmd_of(ptd_t *ptd, unsigned long va)
{
	return pmdp_of(ptd) + pmd_index(va);
}

static inline int pmd_null(pmd_t *pmd)
{
	return !pmd->val;
}

static inline void pmd_set(pmd_t *pmd, unsigned long val)
{
	pmd->val = val;
}

static inline int pmd_alloc(pmd_t *pmd)
{
	void *ptep = kzalloc(PMD_SIZE);

	if (ptep == NULL)
		return -ENOMEM;

	/* link the pmd with its sub-level -> PTE array */
	pmd_set(pmd, virt_to_phys(ptep));
	return 0;
}

static inline void pmd_free(pmd_t *pmd)
{
	/* unlink the pmd with its sub-level -> PTE array */
	kfree(ptep_of(pmd));
	pmd_set(pmd, 0);
}

/*
 * return current reference counter
 */
static inline int pmd_refc(pmd_t *pmd)
{
	return (pmd->val >> REFC_SHIFT) & (PTES_PER_PMD - 1);
}

/*
 * increase reference counter
 */
static inline void pmd_hold(pmd_t *pmd)
{
	pmd->val += (UL(1) << REFC_SHIFT);
}

/*
 * Decrease reference counter
 */
static inline void pmd_put(pmd_t *pmd)
{
	pmd->val -= (UL(1) << REFC_SHIFT);
}

static inline int pmd_type_table(pmd_t *pmd)
{
	return (pmd->val & PMD_TYPE_MASK) == PMD_TYPE_TABLE;
}

static inline int pmd_type_sect(pmd_t *pmd)
{
	return (pmd->val & PMD_TYPE_MASK) == PMD_TYPE_SECT;
}

static inline void pmd_set_type_table(pmd_t *pmd)
{
	pmd->val |= PMD_TYPE_TABLE;
}

static inline void pmd_set_type_sect(pmd_t *pmd)
{
	pmd->val |= PMD_TYPE_SECT;
}

static inline pte_t *pte_of(pmd_t *pmd, unsigned long va)
{
	return ptep_of(pmd) + pte_index(va);
}

static inline void pte_set(pte_t *pte, unsigned long val)
{
	pte->val = val;
}

static inline int pte_null(pte_t *pte)
{
	return !pte->val;
}

static inline void mmu_set_ttbr0(unsigned long ttbr0)
{
	asm volatile (
		"msr ttbr0_el1, %0\n"
		"isb\n"
		:
		: "r" (ttbr0)
		: "memory", "cc");
}

static inline void mmu_set_ttbr1(unsigned long ttbr1)
{
	asm volatile (
		"msr ttbr1_el1, %0\n"
		"isb\n"
		:
		: "r" (ttbr1)
		: "memory", "cc");
}

static inline void mmu_set_mair(unsigned long mair)
{
	asm volatile (
		"msr mair_el1, %0\n"
		"isb\n"
		:
		: "r" (mair)
		: "memory", "cc");
}

static inline void mmu_set_tcr(unsigned long tcr)
{
	asm volatile (
		"msr tcr_el1, %0\n"
		"isb\n"
		:
		: "r" (tcr)
		: "memory", "cc");
}

static inline void mmu_set_sctlr(unsigned long sctlr)
{
	asm volatile (
		"msr sctlr_el1, %0\n"
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
	asm volatile("dsb nshst\n"
				"tlbi vmalle1\n"
				"dsb nsh\n"
				"isb\n"
				: : : "memory", "cc");
}

/*
 * The flush_tlb_asid() invalidates
 * the TLB entries that matches the ASID value.
 */
static inline void flush_tlb_asid(unsigned long asid)
{
	/* Invalidate TLB by ASID (TLBIASIDIS) */
	asm volatile("dsb ishst\n"
				"tlbi aside1is, %0\n"
				"nop;nop\n"
				"dsb ish\n"
				"tlbi aside1is, %0\n"
				"dsb ish\n"
				"isb\n"
				:
				: "r" (asid << ASID_SHIFT)
				: "memory", "cc");
}

#define TLBI_VA(va, asid)	({						\
	unsigned long __va = (va) >> 12;				\
	__va &= 0xfffffffffffUL;						\
	__va |= (unsigned long)(asid) << ASID_SHIFT;	\
	__va; })

/*
 * The flush_tlb_pte() invalidates
 * a single TLB entry that matches the MVA
 * and (or ASID) values provided as an argument
 * to the function.
 *
 * With global entries in the TLB, (kpt() pages)
 * the supplied ASID value is not checked.
 */
static inline void flush_tlb_pte(unsigned long mva,
	unsigned long asid)
{
	unsigned long va = TLBI_VA(mva, asid);

	asm volatile("dsb ishst\n"
		"tlbi vae1is, %0\n"
		"nop;nop\n"
		"dsb ish\n"
		"tlbi vae1is, %0\n"
		"dsb ish\n"
		"isb\n"
		:
		: "r" (va)
		: "memory", "cc");
}

#endif
#endif
