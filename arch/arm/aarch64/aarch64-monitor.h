/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * EL3 - Secure Monitor
 */

#include "aarch64-ctx.h"
#include "aarch64-mmu.h"

/*
 * 1008 bytes for Context - refer to struct thread_ctx_el3. align to 1024..
 * so the stack size is 2048 + 64 - (1024 * 2) = 64 (64B is enough)
 * get from tpidr_el3
 */
#define CONTEXT_SIZE (1024)
#define BUFFER_SIZE (2048 + 64)

/*
 * EL3 -> EL1 SMC call info (to share the rctx pointer with EL1 SMC routine)
 * get from tpidr_el1 -> rctx/sgi
 * when received NS SMC, monitor will trigger SGI, EL1 responses this SGI
 */
#define SMC_SGI_ID (15)

/* save S world per-cpu context (GPR + sys regs + FPU) */
.macro save_s_context
	/* temp save lr / x0 to monitor's stack */
	stp	x30, x0, [sp, #-16]!
	mrs	x0, tpidr_el3
	add	x0, x0, #(CONTEXT_SIZE)
	bl	save_percpu_ctx
	ldp	x30, x1, [sp], #16
	/* save lr / x0 to pre-defined buffer */
	stp	x30, x1, [x0, #16 * 0]
.endm

/* save NS world per-cpu context (GPR + sys regs + FPU) */
.macro save_ns_context
	/* temp save lr / x0 to monitor's stack */
	stp	x30, x0, [sp, #-16]!
	mrs	x0, tpidr_el3
	bl	save_percpu_ctx
	ldp	x30, x1, [sp], #16
	/* save lr / x0 to pre-defined buffer */
	stp	x30, x1, [x0, #16 * 0]
.endm

/* restore S world per-cpu context (GPR + sys regs + FPU) */
.macro restore_s_context
	mrs	x0, tpidr_el3
	add	x0, x0, #(CONTEXT_SIZE)
	bl	restore_percpu_ctx
	/* restore the lr and x0 */
	ldp	x30, x0, [x0, #16 * 0]
.endm

/* restore NS world per-cpu context (GPR + sys regs + FPU) */
.macro restore_ns_context
	mrs	x0, tpidr_el3
	bl	restore_percpu_ctx
	/* restore the lr and x0 */
	ldp	x30, x0, [x0, #16 * 0]
.endm

/*
 * Spectre v2 (CVE-2017-5715): flush branch predictor before eret
 * to NS world, preventing NS from exploiting poisoned BP entries
 * left by the secure world.
 *
 * toggling SCTLR_EL3.M (MMU off then on) forces the CPU to discard
 * speculative state including branch predictor entries. This is lighter
 * than IC IALLU which flushes the entire instruction cache.
 *
 * On real hardware with FEAT_SPECRES (ARMv8.5+), this can be
 * replaced with: sys #3, c7, c3, #4, xzr  (CFP RCTX)
 */
.macro spectre_bp_flush
	stp	x14, x15, [sp, #-16]!
	mrs	x15, sctlr_el3
	bic	x14, x15, #0x1
	msr	sctlr_el3, x14
	isb
	msr	sctlr_el3, x15
	isb
	ldp	x14, x15, [sp], #16
.endm

#if defined(CONFIG_ARM_GICV1) || defined(CONFIG_ARM_GICV2)
#define AARCH64_WITH_LEGACY_GIC
#endif
