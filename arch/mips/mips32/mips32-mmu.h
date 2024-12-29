/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MMU Private Definitions for MIPS32 PageTable/TLB Handing.
 */

#ifndef _MMUPRIV_H
#define _MMUPRIV_H

#include <defs.h>

/*
 * 1 ~ 254, 0 / 255 is reserved
 */
#define ASID_START (1)
#define ASID_END (255)
#define ASID_VALID(_x_)	\
		(((_x_) >= ASID_START) && ((_x_) < ASID_END))
#define ASID_MASK (ASID_END)

#define ASID_RESVD (ASID_END)

#define TLB_PFN_SHIFT (6)
#define TLB_PFN_MASK (~((1 << TLB_PFN_SHIFT) - 1))

#define TLB_GLOBAL (1 << TLB_PFN_SHIFT)
#define TLB_PRIV (0 << TLB_PFN_SHIFT)

#define TLB_VALID (1 << (1 + TLB_PFN_SHIFT))
#define TLB_INVALID (0 << (1 + TLB_PFN_SHIFT))

#define TLB_WRITEABLE (1 << (2 + TLB_PFN_SHIFT))
#define TLB_READONLY (0 << (2 + TLB_PFN_SHIFT))

#define TLB_CACHE_WRITETHROUGH (0 << (3 + TLB_PFN_SHIFT))
#define TLB_CACHE_WRITEBACK (3 << (3 + TLB_PFN_SHIFT))

#define TLB_PROBE_FAIL(x) (((x) & (1 << 31)) != 0)

#define PTD_SHIFT		(22)
#define PTDS_PER_PT		UL(1024)
#define PTE_SHIFT		(10)
#define PTES_PER_PTD	(UL(1) << PTE_SHIFT)

/* dummy */
#define SECTION_SIZE    (UL(1) << PTD_SHIFT)

#ifndef __ASSEMBLY__

#include <cpu.h>
#include <kmalloc.h>
#include <stdbool.h>
#include <trace.h>
#include <cache.h>
#include <page.h>

/*
 * Each PageTable can map 4GB:
 * Each PageTable contains 1024 PageTableDirectory
 * Each PageTableDirectory contains 1024 PageTableEntry
 */
typedef struct {unsigned long val; } pte_t;

/*
 * PTD pointer is aligned to PTD_SIZE
 */
typedef struct {
	/*
	 * reference counter by its PTEs
	 */
	unsigned long refc: PTE_SHIFT;

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
	return ptd->addr ? false : true;
}

static inline void ptd_clear(ptd_t *ptd)
{
	ptd->addr = 0;
	ptd->refc = 0;
}

static inline int ptd_alloc(ptd_t *ptd)
{
	void *t = kzalloc(PTD_SIZE);

	if (t == NULL)
		return -ENOMEM;

	assert(!((uintptr_t)t & (PTD_SIZE - 1)));

	ptd->addr = virt_to_phys(t) >> PTE_SHIFT;
	return 0;
}

static inline void ptd_free(ptd_t *ptd)
{
	kfree(ptep_of(ptd));
	ptd_clear(ptd);
}

/*
 * return current reference counter
 */
static inline int ptd_refc(ptd_t *ptd)
{
	return ptd->refc;
}

/*
 * increase reference counter
 */
static inline void ptd_hold(ptd_t *ptd)
{
	ptd->refc += 1;
}

/*
 * Decrease reference counter
 */
static inline void ptd_put(ptd_t *ptd)
{
	ptd->refc -= 1;
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

static inline unsigned long tlb_get_entryhi(void)
{
	return read_cp0_register(C0_TLBHI);
}

static inline void tlb_set_entryhi(unsigned long val)
{
	write_cp0_register(C0_TLBHI, val);
}

static inline void tlb_set_entrylo0(unsigned long val)
{
	write_cp0_register(C0_TLBLO0, val);
}

static inline void tlb_set_entrylo1(unsigned long val)
{
	write_cp0_register(C0_TLBLO1, val);
}

static inline int tlb_get_index(void)
{
	return read_cp0_register(C0_INDEX);
}

static inline void tlb_set_index(unsigned long val)
{
	write_cp0_register(C0_INDEX, val);
}

static inline void tlb_probe(void)
{
	asm volatile("tlbp; ehb" : : : "memory", "cc");
}

static inline void tlb_write_indexed(void)
{
	asm volatile("tlbwi; ehb" : : : "memory", "cc");
}

static inline void tlb_write_random(void)
{
	asm volatile("tlbwr; ehb" : : : "memory", "cc");
}

static inline int tlb_size(void)
{
	int tlbsize = read_cp0_register_ex(C0_CONFIG, 1);

	tlbsize = (tlbsize >> 25) & 0x3F;

	return tlbsize + 1;
}

/*
 * invalidates a single TLB entry that
 * matches the va and ASID
 */
static inline void flush_tlb_pte(pte_t *pte,
	unsigned long asid, unsigned long va)
{
	long id = -1;
	unsigned long old = tlb_get_entryhi() & ASID_MASK;
	unsigned long vpn = va & (PAGE_MASK << 1);

	pte -= (va != vpn) ? 1 : 0;
	tlb_set_entryhi(vpn | asid);
	tlb_probe();
	id = tlb_get_index();
	if (!TLB_PROBE_FAIL(id)) {
		tlb_set_entrylo0(pte->val >> TLB_PFN_SHIFT);
		pte++;
		tlb_set_entrylo1(pte->val >> TLB_PFN_SHIFT);
		tlb_write_indexed();
	}
	tlb_set_entryhi(old);
}

/*
 * updates a single TLB entry that
 * matches the va and ASID
 */
static inline void update_tlb_pte(pte_t *pte,
	unsigned long asid, unsigned long va)
{
	unsigned long id = -1;
	unsigned long vpn = va & (PAGE_MASK << 1);

	pte -= (va != vpn) ? 1 : 0;
	tlb_set_entrylo0(pte->val >> TLB_PFN_SHIFT);
	pte++;
	tlb_set_entrylo1(pte->val >> TLB_PFN_SHIFT);
	tlb_set_entryhi(vpn | asid);
	tlb_probe();
	id = tlb_get_index();
	if (TLB_PROBE_FAIL(id))
		tlb_write_random();
	else
		tlb_write_indexed();
	tlb_set_entryhi(asid);

}
#endif

#endif
