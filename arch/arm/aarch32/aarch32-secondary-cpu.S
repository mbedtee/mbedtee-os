/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32@ARMV7-A routines for secondary cpus
 */

#include <map.h>

#include "aarch32-mmu.h"
#include "aarch32-asm.h"

/*
 * Wait for @sev
 */
FUNC_START secondary_cpu_wait
#if (CONFIG_NR_CPUS > 1)
	mrc p15, 0, r0, c0, c0, 5 /* mpidr */
	ldr r3, =MPIDR_BITMASK
	and r0, r0, r3
	adr_l r1, cpu_mpid
1:	wfe
	dsb ishst
	ldr r2, [r1]
	and r4, r2, r3
	cmp	r4, r0
	bne 1b
	/* cpu_mpid[31:24] contains the logic cpu-id
	 transfer cpu-id to r0 */
	mov	r0, r2, lsr #24
	ldr r2, =0
	str r2, [r1]
	dsb ish
	bx lr
FUNC_END secondary_cpu_wait

/*
 * Wait for restart sev
 */
FUNC_START secondary_cpu_restart
#if (CONFIG_NR_CPUS > 1)
	/* SCTLR disable cache */
	dsb ishst
	mrc p15, 0, r0, c1, c0, 0
	bic r0, r0, #(1 << 2)  /* D-Cache off */
	bic r0, r0, #(1 << 12) /* I-Cache off */
	mcr p15, 0, r0, c1, c0, 0
	isb

	bl flush_cache_louis

	clrex

	/* ACTLR disable SMP */
	mrc p15, 0, r0, c1, c0, 1
	bic r0, r0, #(1 << 6)
	mcr p15, 0, r0, c1, c0, 1
	isb

#if defined(CONFIG_MMU)
	ldr r11, =VA_OFFSET
	ldr r10, =__memstart
	ldr r10, [r10]
	sub r8, r11, r10

	/* SCTLR Bit19 WXN */
	mrc p15, 0, r12, c1, c0, 0
	bic r12, r12, #(0x80000)
	mcr p15, 0, r12, c1, c0, 0
	isb

	ldr r12, =__kern_early_pgtbl
	sub r12, r12, r8
	mcr p15, 0, r12, c2, c0, 1 	/* S-TTBR1 */
	isb

	/*
	 * Invalidate Local Instruction cache (ICIALLU)
	 * Invalidate Local branch predictor buffer (BPIALL)
	 * Invalidate Local entire TLB (TLBIALL)
	 */
	dsb nshst
	mov r10, #0
	mcr p15, 0, r10, c7, c5, 0
	mcr p15, 0, r10, c7, c5, 6
	mcr p15, 0, r10, c8, c7, 0
	dsb nsh
	isb

	ldr r12, =1f
	sub r12, r12, r8
	bx r12
1:  mrc p15, 0, r12, c1, c0, 0 /* S SCTLR */
	bic r12, r12, #(1 << 0)   /* MMU off */
	mcr p15, 0, r12, c1, c0, 0
	isb

	cps #(MON_MODE)
	set_nsbit r12

	dsb nshst
 	mrc p15, 0, r12, c1, c0, 0 /* NS SCTLR */
	bic r12, r12, #(1 << 0)  /* MMU off */
	bic r12, r12, #(1 << 2)  /* D-Cache off */
	bic r12, r12, #(1 << 12) /* I-Cache off */
	mcr p15, 0, r12, c1, c0, 0
	isb

	unset_nsbit r12
#endif
	bl _start
#else
1:	wfi
	b 1b
#endif
FUNC_END secondary_cpu_restart

/*
 * this jumper only be used for the SoC which can't flexibly
 * assign the secondary CPUs' run entry to the '__memstart'
 *
 * copy this jumper (8-bytes) to the SoC's fix secondary-entry
 * and set '__memstart' to the '.word' of this jumper
 * before release the secondary-cpu
 *
 * 3-level pipe-line, pc = current-pc + 8
 */
.global secondary_trampoline
secondary_trampoline:
	ldr pc, [pc, #-4]
	.word -1
#else
1:	wfi
	b 1b
#endif
