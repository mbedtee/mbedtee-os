/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ASM macros for AArch64 context save/restore
 */

#ifndef _AARCH64_CTX_H
#define _AARCH64_CTX_H

#include "aarch64-asm.h"

.macro prepare_thread_ksp rt
	mrs \rt, tpidr_el1
	ldr \rt, [\rt, #(PERCPU_THREAD_KSP)]
.endm

/*
 * -- for syscall/EL0 exception
 * save the context to thread's ksp
 */
.macro save_thread_context_el0
	str x7, [sp, #-8]! /* save x7 */
	prepare_thread_ksp x7
	sub x7, x7, #(THREAD_CTX_SIZE)
	stp	x30, x0, [x7] /* save lr / x0 */
	mov x0, x7
	ldr x7, [sp], #8 /* restore x7*/

	bl save_thread_ctx
.endm

/*
 * -- for interrupt/EL1 exception
 * save the context to common EL1 IRQ SP
 */
.macro save_thread_context
	sub sp, sp, #(THREAD_CTX_SIZE)
	stp	x30, x0, [sp] /* save lr / x0 */
	mov x0, sp

	bl save_thread_ctx
.endm

/* restore the thread context */
.macro restore_thread_context
	bl sched_sighandle
	bl restore_thread_ctx
	/* restore lr and x0 */
	ldp	x30, x0, [x0]
.endm

#endif
