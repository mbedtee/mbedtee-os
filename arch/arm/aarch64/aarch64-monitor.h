/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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

/* save S world per-cpu context */
.macro save_s_context
	/* temp save lr / x0 to monitor's stack */
	stp	x30, x0, [sp, #-16]!
	mrs x0, tpidr_el3
	add x0, x0, #(CONTEXT_SIZE)
	bl save_percpu_ctx
	ldp	x30, x1, [sp], #16
	/* save lr / x0 to pre-defined buffer */
	stp	x30, x1, [x0, #16 * 0]
.endm

/* save NS world per-cpu context */
.macro save_ns_context
	/* temp save lr / x0 to monitor's stack*/
	stp	x30, x0, [sp, #-16]!
	mrs x0, tpidr_el3
	bl save_percpu_ctx
	ldp	x30, x1, [sp], #16
	/* save lr / x0 to pre-defined buffer */
	stp	x30, x1, [x0, #16 * 0]
.endm

/* restore S world per-cpu context */
.macro restore_s_context
	mrs x0, tpidr_el3
	add x0, x0, #(CONTEXT_SIZE)
	bl restore_percpu_ctx
	/* restore the lr and x0 */
	ldp	x30, x0, [x0, #16 * 0]
.endm

/* restore NS world per-cpu context */
.macro restore_ns_context
	mrs x0, tpidr_el3
	bl restore_percpu_ctx
	/* restore the lr and x0 */
	ldp	x30, x0, [x0, #16 * 0]
.endm

#if defined(CONFIG_ARM_GICV1) || defined(CONFIG_ARM_GICV2)
#define AARCH64_WITH_LEGACY_GIC
#endif
