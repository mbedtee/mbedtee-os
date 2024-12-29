/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MMU Private Definitions for Sv32 PageTable/TLB Handing.
 */

#ifndef _MMUPRIV_H
#define _MMUPRIV_H

#include <map.h>
#include <defs.h>
#include <page.h>

/*
 * HW ASID is 9-bit width
 * 1 ~ 510, 0 / 511 is reserved
 */
#define ASID_START (1)
#define ASID_END (511)
#define ASID_VALID(_x_)	\
		(((_x_) >= ASID_START) && ((_x_) < ASID_END))
#define ASID_MASK (ASID_END)

#define ASID_RESVD (ASID_END)

#define PTD_SHIFT		(22)
#define PTDS_PER_PT		UL(1024)
#define PTE_SHIFT		(10)
#define PTES_PER_PTD	(UL(1) << PTE_SHIFT)

#define PTE_VALID       (UL(1) << 0)
#define PTE_READ        (UL(1) << 1)
#define PTE_WRITE       (UL(1) << 2)
#define PTE_EXECUTABLE  (UL(1) << 3)
#define PTE_USER        (UL(1) << 4)
#define PTE_GLOBAL      (UL(1) << 5)
#define PTE_ACCESSED    (UL(1) << 6)
#define PTE_DIRTY       (UL(1) << 7)

#define PTD_VALID       (UL(1) << 0)
#define PTD_USER        (UL(1) << 4)
#define PTD_GLOBAL      (UL(1) << 5)
#define PTD_ACCESSED    (UL(1) << 6)
#define PTD_DIRTY       (UL(1) << 7)

#define PTE_RWX         (PTE_READ | PTE_WRITE | PTE_EXECUTABLE)

/*
 * section size
 */
#define SECTION_SHIFT	(PTD_SHIFT)
#define SECTION_SIZE	(UL(1) << SECTION_SHIFT)
#define SECTION_MASK	(~(SECTION_SIZE - 1))

#define SECTION_MAP_FLAGS (PTD_VALID | PTD_ACCESSED | PTD_DIRTY | PTE_RWX)

#define PPN_BIAS		(2)

#define SATP_MODE       (UL(1) << 31)
#define SATP_ASID_SHIFT (22)

#define SATP_VAL(pt) (SATP_MODE | (virt_to_phys((pt)->ptds) >> PAGE_SHIFT) | \
			(((unsigned long)((pt)->asid)) << SATP_ASID_SHIFT))

#ifndef __ASSEMBLY__

#include <cpu.h>
#include <kmalloc.h>
#include <stdbool.h>
#include <trace.h>
#include <cache.h>
#include <page.h>

extern unsigned long __kern_early_pgtbl[];

/*
 * Each PageTable can map 4GB:
 * Each PageTable contains 1024 PageTableDirectory
 * Each PageTableDirectory contains 1024 PageTableEntry
 */
typedef struct {unsigned long val; } pte_t;
typedef struct {unsigned long val; } ptd_t;

#define PTD_SIZE		(PTES_PER_PTD * sizeof(pte_t))
#define PT_SIZE			(PTDS_PER_PT * sizeof(ptd_t))

#define ptd_index(x)	((x) >> PTD_SHIFT)
#define pte_index(x)	(((x) >> PAGE_SHIFT) & (PTES_PER_PTD - 1))

#define ptdp_of(pt)		((ptd_t *)(pt)->ptds)
#define ptep_of(ptd)	((pte_t *)phys_to_virt((((ptd)->val) << PPN_BIAS) & \
						((unsigned long)(~(PTD_SIZE - 1)))))

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
	void *t = kzalloc(PTD_SIZE);

	if (t == NULL)
		return -ENOMEM;

	/* link the ptd with its sub-level -> PTE array */
	ptd_set(ptd, virt_to_phys(t) >> PPN_BIAS);
	return 0;
}

static inline void ptd_free(ptd_t *ptd)
{
	kfree(ptep_of(ptd));
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
		unsigned short *refc = (pt->refc +
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
		unsigned short *refc = (pt->refc +
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
		unsigned short *refc = (pt->refc +
			ptd_index(va) * sizeof(short));

		*refc -= 1;
	}
}

/*
 * Mask the refc, get the real pointer
 */
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

#endif

#endif
