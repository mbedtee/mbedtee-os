/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * EL3 - Secure Monitor Exception handling
 * SMC/FIQ routines for TEE/REE world ctx switching
 *
 * Support AArch64 + GICv3/GICv4
 * Support AArch64 + GICv2 (weird architectured SoC)
 */

#include "aarch64-monitor.h"

.align 11
.global monitor_vectors
monitor_vectors:
/* Current EL with SP0 */
	b .
	.align 7
	b .
	.align 7
	b .
	.align 7
	b .
	.align 7
/* Current EL with SPx */
monitor_synchronous_el3:
	b .
	.align 7
monitor_irq_el3:
	b .
	.align 7
monitor_fiq_el3:
	b .
	.align 7
monitor_serror_el3:
	b .
	.align 7
/* Lower EL using AArch64 */
monitor_synchronous:
	is_nsbit_unset x15
	beq smc_called_from_s
	bne smc_called_from_ns
	.align 7
monitor_irq:
	b .
	.align 7
monitor_fiq:
	is_nsbit_unset x15
	beq fiq_called_from_s
	bne fiq_called_from_ns
	.align 7

monitor_serror:
	b .
	.align 7
/* Lower EL using AArch32 */
	b .
	.align 7
	b .
	.align 7
	b .
	.align 7
	b .
	.align 7
	b .

set_cntfrq:
	/* Set the GenericTimer Counter FRQ @ x1 */
	msr cntfrq_el0, x1
	/* save it to global for secondary CPUs */
	adr_l x15, __cntfrq
	str x1, [x15]
	eret
set_legacy_gic_base:
#if defined(AARCH64_WITH_LEGACY_GIC)
	adr_l x15, __gicd_sgir
	str w1, [x15]
	adr_l x15, __gicc_ctlr
	str w2, [x15]
#endif
	eret

/*
 * x0 == 0: resume NS
 * x0 == others: TEE2Monitor calls
 *   x0 == 1: set GeneriTimer Counter FRQ
 *   x0 == 2: secondary_cpu_restart
 *   x0 == 3: set the legacy GICD/GICC for 'AArch64+GICv2' SoC
 */

smc_called_from_s:
	cbz x0, switch_to_ns
	cmp x0, #1
	beq set_cntfrq
	cmp x0, #2
	beq secondary_cpu_restart
	cmp x0, #3
	beq set_legacy_gic_base
	b .

/* AArch64 + GICv3 or v4 */
#if !defined(AARCH64_WITH_LEGACY_GIC)
smc_called_from_ns:
	save_ns_context
	unset_nsbit x15
/* trigger a IPI call for notifying S world -------- start */
	/* fill the SGIR_VAL */
	ldr x13, =(SMC_SGI_ID) /* GIC SGI 15 */
	lsl x13, x13, #24

	ldr x9, =0xff
	mrs x14, mpidr_el1
	and x15, x9, x14
	ldr x10, =1
	lsl x15, x10, x15
	orr x15, x13, x15

	and x10, x9, x14, lsr #32
	and x11, x9, x14, lsr #16
	and x12, x9, x14, lsr #8

	orr x15, x15, x10, lsl #48
	orr x15, x15, x11, lsl #32
	orr x15, x15, x12, lsl #16

	/* icc_write_sgi1r */
	dsb ishst
	msr S3_0_C12_C11_5, x15
/* trigger a IPI call for notifying S world ---------- end */
	restore_s_context
	clrex
	eret

fiq_called_from_s:
	save_s_context
	set_nsbit x15
	restore_ns_context
	clrex
	eret

fiq_called_from_ns:
	save_ns_context
	unset_nsbit x15
	restore_s_context
	clrex
	eret

switch_to_ns:
#if defined(CONFIG_REE)
	save_s_context
	set_nsbit x15
	restore_ns_context
	clrex
#endif
	eret

#else

/* group 0/1 and fiq enable bits */
#define GICC_FIQ_EN 0x0B
#define GICC_FIQ_DIS 0x03

switch_to_ns:
#if defined(CONFIG_REE)
	save_s_context
	adr_l x9, __gicc_ctlr
	ldr w9, [x9]
	ldr w10, =GICC_FIQ_EN
	str w10, [x9]
	set_nsbit x15
	restore_ns_context
	clrex
#endif
	eret

/* AArch64 + GICv2 */
fiq_called_from_s:
	stp x9, x10, [sp, #-16]!
	adr_l x9, __gicc_ctlr
	ldr w9, [x9]
	ldr w10, =GICC_FIQ_DIS
	str w10, [x9]
	ldp x9, x10, [sp], #16
	eret

fiq_called_from_ns:
	save_ns_context
	unset_nsbit x15
	adr_l x9, __gicc_ctlr
	ldr w9, [x9]
	ldr w10, =GICC_FIQ_DIS
	str w10, [x9]
	restore_s_context
	clrex
	eret

smc_called_from_ns:
	save_ns_context
	unset_nsbit x15
/* trigger a IPI call for notifying S world -------- start */
	ldr x9, =0xff
	mrs x14, mpidr_el1
	and x15, x9, x14
	ldr x10, =(1 << 16)
	lsl x15, x10, x15
	ldr x13, =(SMC_SGI_ID)
	orr x13, x13, x15
	adr_l x14, __gicd_sgir
	ldr w14, [x14]
	dsb ishst
	str w13, [x14]
/* trigger a IPI call for notifying S world ---------- end */
	restore_s_context
	clrex
	eret

	.bss
	.align 2
__gicc_ctlr:
	.word 0
__gicd_sgir:
	.word 0
#endif
