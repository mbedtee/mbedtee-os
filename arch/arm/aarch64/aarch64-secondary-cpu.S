/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * routines for secondary cpus
 */

#include <map.h>
#include <generated/autoconf.h>

#include "aarch64-asm.h"

/*
 * sev - wait for event
 */
FUNC_START secondary_cpu_wait
#if (CONFIG_NR_CPUS > 1)
	ldr x3, =MPIDR_BITMASK
	mrs x0, mpidr_el1
	and x0, x0, x3
	adr_l x1, cpu_mpid
1:	wfe
	dsb ishst
	ldr x2, [x1]
	and x5, x2, x3
	cmp x5, x0
	bne 1b

	/* invalid the cpu_mpid */
	ldr x3, =-1
	str x3, [x1]
	dsb ish

	/* cpu_mpid[63:40] contains the logic cpu-id
	 transfer cpu-id to x0 */
	lsr x0, x2, 40
	br lr
#else
1:	wfi
	b 1b
#endif
FUNC_END secondary_cpu_wait

/*
 * Wait for restart sev
 */
FUNC_START secondary_cpu_restart
#if (CONFIG_NR_CPUS > 1)
	mrs x0, sctlr_el1
	bic x0, x0, #(1 << 0) /* Translation off */
	bic x0, x0, #(1 << 2) /* D-Cache off */
	bic x0, x0, #(1 << 12) /* I-Cache off */
	msr sctlr_el1, x0
	isb

	mrs x0, sctlr_el2
	bic x0, x0, #(1 << 0) /* Translation off */
	bic x0, x0, #(1 << 2) /* D-Cache off */
	bic x0, x0, #(1 << 12) /* I-Cache off */
	msr sctlr_el2, x0
	isb

	mrs x0, sctlr_el3
	bic x0, x0, #(1 << 0) /* Translation off */
	bic x0, x0, #(1 << 2) /* D-Cache off */
	bic x0, x0, #(1 << 12) /* I-Cache off */
	msr sctlr_el3, x0
	isb

	bl flush_cache_louis

	clrex
 	smp_disable
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
 * copy this jumper (24-bytes) to the SoC's fix secondary-entry
 * and set '__memstart' to the '.dword' of this jumper
 * before release the secondary-cpu
 */
.global secondary_trampoline
secondary_trampoline:
#if (CONFIG_NR_CPUS > 1)
	adr_l x0, 1f
	ldr lr, [x0]
	ret
1:	.dword -1
#else
1:	wfi
	b 1b
#endif
