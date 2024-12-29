/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV MMU common header file.
 */

#ifndef _MMU_RISCV_H
#define _MMU_RISCV_H

#include <generated/autoconf.h>

#if defined(CONFIG_MMU)

#if defined(CONFIG_MMU_SV32)
#include "sv32-mmu.h"
#elif defined(CONFIG_MMU_SV39)
#include "sv39-mmu.h"
#endif

#ifndef __ASSEMBLY__

#include <uaccess.h>
#include "riscv-tlb.h"

/*
 * sync va's mapping from kpt() to pt
 * return synced or not
 */
static inline int pt_sync(struct pt_struct *pt,
	unsigned long va)
{
#if defined(CONFIG_USER)
	ptd_t ptd;
	struct pt_struct *kpagetbl = kpt();

	if (pt == kpagetbl || user_addr(va))
		return false;

	ptd = *ptd_of(kpagetbl, va);
	if (ptd_null(&ptd))
		return false;

	*ptd_of(pt, va) = ptd;
/*	flush_tlb_pte(va, kpagetbl->asid); */

	return true;
#endif
	return false;
}

static inline void ptd_sync_clear(unsigned long va)
{
#if defined(CONFIG_USER)
	struct process *proc = NULL;
	unsigned long flags = 0;

	if (user_addr(va))
		return;

	spin_lock_irqsave(&__plock, flags);

	list_for_each_entry(proc, &__procs, node)
		ptd_set(ptd_of(proc->pt, va), 0);

	spin_unlock_irqrestore(&__plock, flags);
#endif
}

static inline void mmu_enable(struct pt_struct *pt)
{
	write_csr(satp, SATP_VAL(pt));
}

#endif

#endif

#endif
