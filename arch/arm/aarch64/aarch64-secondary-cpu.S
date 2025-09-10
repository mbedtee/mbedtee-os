/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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
	adr_l x1, cpu_power_id
1:	wfe
	dsb ishst
	ldr x2, [x1]
	and x5, x2, x3
	cmp x5, x0
	bne 1b

	/* Invalidate the cpu_power_id */
	ldr x3, =-1
	str x3, [x1]
	dsb ish

	/* cpu_power_id[63:40] contains the logical CPU ID,
	 transfer the CPU ID to x0 */
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
	/* MMU + D-Cache + I-Cache off for EL1/EL2/EL3 */
	mov x1, #((1 << 0) | (1 << 2) | (1 << 12))

	mrs x0, sctlr_el1
	bic x0, x0, x1
	msr sctlr_el1, x0
	isb

	mrs x0, sctlr_el2
	bic x0, x0, x1
	msr sctlr_el2, x0
	isb

	mrs x0, sctlr_el3
	bic x0, x0, x1
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
 * This trampoline is only used for SoCs that cannot flexibly
 * assign the secondary CPUs' run entry to '__memstart'.
 *
 * Copy this trampoline (24 bytes) to the SoC's fixed secondary-entry
 * and set '__memstart' to the '.dword' of this trampoline (offset 0x10)
 * before releasing the secondary CPU.
 */
.align 3
.global secondary_trampoline
secondary_trampoline:
#if (CONFIG_NR_CPUS > 1)
	adr x0, 1f
	nop
	ldr lr, [x0]
	ret
1:	.dword 0
#else
1:	wfi
	b 1b
#endif

.data
.balign BYTES_PER_LONG, 0
.global cpu_power_id
cpu_power_id:
	.fill 1, BYTES_PER_LONG, 0
