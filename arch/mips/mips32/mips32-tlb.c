// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 TLB maintenance
 */

#include <errno.h>
#include <trace.h>

#include <mips32-mmu.h>
#include <mips32-tlb.h>

/*
 * walks the page table and refills a TLB entry
 * that matches the va in this given page table
 */
int tlb_refill(struct pt_struct *pt,
	unsigned long va, int prot)
{
	pte_t *pte = NULL;
	ptd_t *ptd = NULL;

	va &= PAGE_MASK;

	ptd = ptd_of(pt, va);
	if (ptd_null(ptd))
		return -ENOENT;

	pte = pte_of(ptd, va);
	if (pte_null(pte))
		return -ENOENT;

	if (!(pte->val & TLB_VALID))
		return -ENOENT;

	if ((prot == PG_RW) && !(pte->val & TLB_WRITEABLE))
		return -EACCES;

	update_tlb_pte(pte, pt->asid, va);
	return 0;
}

/*
 * refills all TLB entries with invalidate value
 */
void tlb_invalidate_all(void)
{
	unsigned long old = 0;
	unsigned long i = 0, max = 0;
	unsigned long flags = 0;

	local_irq_save(flags);

	max = tlb_size();
	old = tlb_get_entryhi();

	tlb_set_entrylo0(0);
	tlb_set_entrylo1(0);

	for (i = 0; i < max; i++) {
		tlb_set_entryhi((KSEG0 + (i << (PAGE_SHIFT + 1))) | (1UL << 10));
		tlb_set_index(i);
		tlb_write_indexed();
	}

	tlb_set_entryhi(old);

	local_irq_restore(flags);
}
