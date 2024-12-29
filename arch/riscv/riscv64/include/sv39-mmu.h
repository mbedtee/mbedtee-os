/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MMU Private Definitions for Sv39 PageTable/TLB Handing.
 */

#ifndef _MMUPRIV_H
#define _MMUPRIV_H

#include <map.h>
#include <defs.h>
#include <page.h>

/*
 * HW ASID is 16-bit width
 * 1 ~ 510, 0 / 511 is reserved
 */
#define ASID_START (1)
#define ASID_END (511)
#define ASID_VALID(_x_)	\
		(((_x_) >= ASID_START) && ((_x_) < ASID_END))
#define ASID_MASK (ASID_END)

#define ASID_RESVD (ASID_END)

/*
 * Each PageTable can map 512GB (39-bits AddressSpace, 4KB PageSize):
 * Each PageTable has 3 translation level, each level has 512 entries
 * Each PageTable contains 512 PageTableDirectory (PTD)
 * Each PageTableDirectory contains 512 PageTableMiddleDirectory (PMD)
 * Each PageTableMiddleDirectory contains 512 PageTableEntry (PTE)
 *
 * ptd -> pmd -> pte
 *
 */
#define PTE_SHIFT		((PAGE_SHIFT - 3) * 1 + 3) /* [20:12] 4KB */
#define PTES_PER_PMD	(UL(1) << (PAGE_SHIFT - 3))

#define PMD_SHIFT		((PAGE_SHIFT - 3) * 2 + 3) /* [29:21] 2MB */
#define PMDS_PER_PTD	(PTES_PER_PMD)

#define PTD_SHIFT		((PAGE_SHIFT - 3) * 3 + 3) /* [38:30] 1GB */
#define PTDS_PER_PT		(PTES_PER_PMD)


#define PTE_VALID       (UL(1) << 0)
#define PTE_READ        (UL(1) << 1)
#define PTE_WRITE       (UL(1) << 2)
#define PTE_EXECUTABLE  (UL(1) << 3)
#define PTE_USER        (UL(1) << 4)
#define PTE_GLOBAL      (UL(1) << 5)
#define PTE_ACCESSED    (UL(1) << 6)
#define PTE_DIRTY       (UL(1) << 7)

#define PMD_VALID       (UL(1) << 0)
#define PMD_USER        (UL(1) << 4)
#define PMD_GLOBAL      (UL(1) << 5)
#define PMD_ACCESSED    (UL(1) << 6)
#define PMD_DIRTY       (UL(1) << 7)

#define PTE_RWX         (PTE_READ | PTE_WRITE | PTE_EXECUTABLE)

#define PTD_VALID       (UL(1) << 0)

/*
 * section size
 */
#define SECTION_SHIFT	(PMD_SHIFT)
#define SECTION_SIZE	(UL(1) << SECTION_SHIFT)
#define SECTION_MASK	(~(SECTION_SIZE - 1))

#define SECTION_MAP_FLAGS (PMD_VALID | PMD_ACCESSED | PMD_DIRTY | PTE_RWX)

#define PPN_BIAS		(2)

#define SATP_ASID_SHIFT (44)
#define SATP_MODE       (UL(8) << 60) /* Sv39 */

#define SATP_VAL(pt) (SATP_MODE | (((long)((pt)->asid)) << SATP_ASID_SHIFT) | \
			(virt_to_phys((pt)->ptds) >> PAGE_SHIFT))

#ifndef __ASSEMBLY__

#include <cpu.h>
#include <kmalloc.h>
#include <stdbool.h>
#include <trace.h>
#include <cache.h>
#include <page.h>

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
#define pmdp_of(ptd)	((pmd_t *)phys_to_virt((((ptd)->val) << PPN_BIAS) & \
						((unsigned long)(~(PTD_SIZE - 1)))))
#define ptep_of(pmd)	((pte_t *)phys_to_virt((((pmd)->val) << PPN_BIAS) & \
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

static inline void ptd_setflags(ptd_t *ptd, unsigned long flags)
{
	ptd->val |= flags;
}

static inline int ptd_alloc(ptd_t *ptd)
{
	void *pmdp = kzalloc(PTD_SIZE);

	if (pmdp == NULL)
		return -ENOMEM;

	/* link the ptd with its sub-level -> PMD array */
	ptd_set(ptd, virt_to_phys(pmdp) >> PPN_BIAS);
	return 0;
}

static inline void ptd_free(ptd_t *ptd)
{
	/* unlink the ptd with its sub-level -> PMD array */
	kfree(pmdp_of(ptd));
	ptd_set(ptd, 0);
}

/*
 * a table points to next level
 */
static inline int ptd_type_table(ptd_t *ptd)
{
	return (ptd->val & PTE_RWX) == 0;
}

/*
 * return current reference counter
 */
static inline int ptd_refc(struct pt_struct *pt,
	unsigned long va)
{
	if (pt->refc) {
		unsigned short *refc = (pt->ptds +
			ptd_index(va) * sizeof(short));

		return *refc;
	}
	return -1;
}

/*
 * increase reference counter
 */
static inline void ptd_hold(struct pt_struct *pt,
	unsigned long va)
{
	if (pt->refc) {
		unsigned short *refc = (pt->ptds +
			ptd_index(va) * sizeof(short));

		*refc += 1;
	}
}

/*
 * Decrease reference counter
 */
static inline void ptd_put(struct pt_struct *pt,
	unsigned long va)
{
	if (pt->refc) {
		unsigned short *refc = (pt->ptds +
			ptd_index(va) * sizeof(short));

		*refc -= 1;
	}
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

static inline void pmd_setflags(pmd_t *pmd, unsigned long flags)
{
	pmd->val |= flags;
}

static inline int pmd_alloc(pmd_t *pmd)
{
	void *ptep = kzalloc(PMD_SIZE);

	if (ptep == NULL)
		return -ENOMEM;

	/* link the pmd with its sub-level -> PTE array */
	pmd_set(pmd, virt_to_phys(ptep) >> PPN_BIAS);
	return 0;
}

static inline void pmd_free(pmd_t *pmd)
{
	/* unlink the pmd with its sub-level -> PTE array */
	kfree(ptep_of(pmd));
	pmd_set(pmd, 0);
}

static inline int pmd_type_table(pmd_t *pmd)
{
	return (pmd->val & PTE_RWX) == 0;
}

#define pmd_refc_offset(va) (((va - KERN_VA_START) >> \
	PMD_SHIFT) * sizeof(short))

/*
 * return current reference counter
 */
static inline int pmd_refc(struct pt_struct *pt,
	unsigned long va)
{
	if (pt->refc) {
		unsigned short *refc = pt->refc + pmd_refc_offset(va);
		return *refc;
	}
	return -1;
}

/*
 * increase reference counter
 */
static inline void pmd_hold(struct pt_struct *pt,
	unsigned long va)
{
	if (pt->refc) {
		unsigned short *refc = pt->refc + pmd_refc_offset(va);
		*refc += 1;
	}
}

/*
 * Decrease reference counter
 */
static inline void pmd_put(struct pt_struct *pt,
	unsigned long va)
{
	if (pt->refc) {
		unsigned short *refc = pt->refc + pmd_refc_offset(va);
		*refc -= 1;
	}
}

/*
 * Mask the refc, get the real pointer
 */
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

#endif

#endif
