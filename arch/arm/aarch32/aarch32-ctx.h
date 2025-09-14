/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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

/*
 * switch to the percpu common stack (IRQ stack)
 */
.macro prepare_irq_ksp
	mrc p15, 0, sp, c13, c0, 4
	ldr sp, [sp, #(PERCPU_IRQ_KSP)]
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

/*
 * vstm_vfp / vldm_vfp - store/load all VFP registers with writeback.
 * On VFP-D16 platforms the d16-d31 region is skipped by advancing the
 * pointer, keeping the struct layout identical to VFP-D32 builds.
 */
.macro vstm_vfp reg
	vstmia \reg!, {d0-d15}
#if defined(VFP_D32)
	vstmia \reg!, {d16-d31}
#endif
.endm

.macro vldm_vfp reg
	vldmia \reg!, {d0-d15}
#if defined(VFP_D32)
	vldmia \reg!, {d16-d31}
#endif
.endm

/* save the thread context */
.macro save_thread_context
	push {r12, lr}
	sub r12, sp, #(GPR_CTX_SIZE - (2 * BYTES_PER_LONG))

	bl save_thread_ctx
	bl save_fpu_ctx_eager
	sub sp, sp, #(GPR_CTX_SIZE)
	mov r0, sp
.endm

/*
 * restore the thread context for returning to NS,
 * donot handle the secure-world signal
 */
.macro restore_thread_context
	bl restore_thread_ctx
	/* resume the original sp */
	add sp, sp, #(GPR_CTX_SIZE)
.endm

#endif
