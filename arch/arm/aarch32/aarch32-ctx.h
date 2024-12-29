/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ASM macros for AArch32@ARMV7-A context save/restore
 */

#ifndef _AARCH32_CTX_H
#define _AARCH32_CTX_H

#include "aarch32-asm.h"

.macro tee_context_ptr rd
	mrc p15, 0, \rd, c13, c0, 4

	add \rd, \rd, #(PERCPU_TEE_CTX)
.endm

.macro ree_context_ptr rd
	mrc p15, 0, \rd, c13, c0, 4

	add \rd, \rd, #(PERCPU_REE_CTX)
.endm

/*
 * switch to the uthread's kernel stack @ TPIDRPRW->ksp
 */
.macro prepare_syscall_ksp
	mrc p15, 0, sp, c13, c0, 4
	ldr sp, [sp, #(PERCPU_THREAD_KSP)]
.endm

.macro prepare_abort_ksp
	mrs sp, spsr
	and sp, sp, #(SYS_MODE)
	cmp sp, #(USR_MODE)
	mrc p15, 0, sp, c13, c0, 4
	/* PERCPU_THREAD_KSP: might sleep when handling the vm_fault */
	ldreq sp, [sp, #(PERCPU_THREAD_KSP)]
	ldrne sp, [sp, #(PERCPU_IRQ_KSP)]
.endm

/* save the thread context */
.macro save_thread_context
	push {r12, lr}
	sub r12, sp, #(THREAD_CTX_SIZE - (2 * BYTES_PER_LONG))

	bl save_thread_ctx
	sub sp, sp, #(THREAD_CTX_SIZE)
	mov r0, sp
.endm

/*
 * restore the thread context for returning to NS,
 * donot handle the secure-world signal
 */
.macro restore_thread_context
	bl restore_thread_ctx
	/* resume the original sp */
	add sp, sp, #(THREAD_CTX_SIZE)
.endm

#endif
