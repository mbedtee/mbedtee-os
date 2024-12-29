/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ASM macros for mips32-ctx save/restore
 */

#ifndef _MIPS32_ASM_MACROS_H
#define _MIPS32_ASM_MACROS_H

#include <cpu.h>
#include <regdef.h>
#include <generated/asm-offsets.h>

.macro FUNC_START name
	.global \name
	.type \name, % function
\name :
.endm

.macro FUNC_END name
	.size \name, . -\name
.endm

/*
 * Currently only support one processor for MIPS32
 */
.macro prepare_thread_ksp rd
	la		\rd, percpu_dt
	lw		\rd, PERCPU_THREAD_KSP(\rd)
.endm

.macro prepare_irq_ksp rd
	la		\rd, percpu_dt
	lw		\rd, PERCPU_IRQ_KSP(\rd)
.endm

.macro percpu_asid rd
	la		\rd, percpu_dt
	lw		\rd, PERCPU_DATA_ASID(\rd)
.endm

/*
 * save the thread context
 */
.macro save_thread_context
	mfc0	k0, C0_STATUS
	sll		k0, 27
	move	k1, sp     /*  continues on the original sp if from kernel */
	bgez	k0, 1f     /* great than zero means: we come from kernel */
	move	k0, sp

	prepare_thread_ksp k1 /* PERCPU_THREAD_KSP */
1 : addi	sp, k1, -THREAD_CTX_SIZE

	/*
	 * old sp -> k0
	 * old ra -> k1
	 */
	move	k1, ra

	bal		save_thread_ctx
	nop
.endm

/*
 * 1. simulate exception
 * 2. save the thread context with IRQ SP
 */
.macro save_thread_context_sched
	/* simulate exception */
	di		k1
	ori		k1, STAT_EXL
	mtc0	k1, C0_STATUS
	mtc0	ra, C0_EPC

	ehb

	move	k0, sp
	move	k1, ra

	prepare_irq_ksp sp /* PERCPU_IRQ_KSP */

	/*
	 * old sp -> k0
	 * old ra -> k1
	 */
	bal		save_thread_ctx
	addi	sp, -THREAD_CTX_SIZE
.endm

/*
 * restore the thread context
 */
.macro restore_thread_context
	/* sighandle with ctx @ v0, use v0 as sp top */
	move sp, v0

	bal sched_sighandle
	move a0, v0

	/* restore context @ v0 */
	bal restore_thread_ctx
	move sp, v0

	/* clear k0/k1 */
	move k0, zero
	move k1, zero
.endm

/* used for when making a pie kernel, pie is currently not in use */
.macro set_gp
	bal	1f
	nop
	.word _gp
1 : lw	gp, 0(ra)
.endm

/*
 * although the pie kernel is not in use,
 * but to keep the compatibility, still use t9 as jumper.
 * In case when you building a pie kernel, remember to add
 * the gap between link/run addresses to t9
 */
.macro jump lable
	la		t9, \lable

	jalr	t9
	nop
.endm

.macro align_ebase
	.balign 4096, 0
	b exception_entry
	.balign 256, 0
	.word 0
	.balign 128, 0
.endm

#endif
