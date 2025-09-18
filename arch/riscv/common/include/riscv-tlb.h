/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>
 * RISCV TLB flush.
 */

#ifndef _TLB_RISCV_H
#define _TLB_RISCV_H

#include <cpu.h>
#include <generated/autoconf.h>

#if !defined(__ASSEMBLY__)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * local_hart_only - Global mappings are not ensured
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
 * Invalidates the TLB entry for va across all ASIDs (G-bit global pages).
 * Uses x0 (zero register) as rs2 per RISCV spec, which means all ASIDs.
 * Required for kernel pages mapped with PTE_GLOBAL/PTD_GLOBAL (G bit).
 */
static inline void local_flush_tlb_global_pte(unsigned long va)
{
	asm volatile("sfence.vma %0, zero" : : "r" (va) : "memory", "cc");
}

/*
 * local_hart_only - Global mappings are not ensured
 *
 * invalidates all the TLB entries that matches the ASID
 */
static inline void local_flush_tlb_asid(unsigned long asid)
{
	asm volatile("sfence.vma zero, %0"
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
 * Invalid whole instruction cache.
 * Standard fence.i suffices for most implementations.
 * T-Head requires th.icache.iall + th.sync.s for full I-cache invalidation.
 */
static inline void local_flush_icache_all(void)
{
	asm volatile("fence.i" : : : "memory", "cc");

	if (thead_supported()) {
		/* th.icache.iall: 0x0100000b, th.sync.s: 0x0190000b */
		asm volatile(
			".long 0x0100000b\n"
			".long 0x0190000b\n"
			: : : "memory");
	}
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

#ifdef __cplusplus
}
#endif

#endif /* !__ASSEMBLY__ */

#endif /* _TLB_RISCV_H */
