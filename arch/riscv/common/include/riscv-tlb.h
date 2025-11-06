/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV TLB flush.
 */

#ifndef _TLB_RISCV_H
#define _TLB_RISCV_H

#include <generated/autoconf.h>

#ifndef __ASSEMBLY__

/*
 * local_hart_only
 *
 * invalidates a single TLB entry that matches the va and ASID
 */
static inline void local_flush_tlb_pte(unsigned long va,
		unsigned long asid)
{
	asm volatile("sfence.vma %0, %1"
			: : "r" (va), "r" (asid) : "memory", "cc");
}

/*
 * local_hart_only
 *
 * invalidates all the TLB entries that matches the ASID
 */
static inline void local_flush_tlb_asid(unsigned long asid)
{
	asm volatile("sfence.vma x0, %0"
		: : "r" (asid) : "memory", "cc");
}

/*
 * local_hart_only
 *
 * invalidates all the TLB entries
 */
static inline void local_flush_tlb_all(void)
{
	asm volatile("sfence.vma" : : : "memory", "cc");
}

/*
 * local_hart_only
 *
 * Invalid whole instruction cache
 */
static inline void local_flush_icache_all(void)
{
	asm volatile("fence.i" : : : "memory", "cc");
}

#if CONFIG_NR_CPUS > 1
void flush_tlb_all(void);
void flush_tlb_asid(unsigned long asid);
void flush_tlb_pte(unsigned long va,	unsigned long asid);
void flush_icache_all(void);
#else
#define flush_tlb_all local_flush_tlb_all
#define flush_tlb_asid local_flush_tlb_asid
#define flush_tlb_pte local_flush_tlb_pte
#define flush_icache_all local_flush_icache_all
#endif

#endif

#endif
