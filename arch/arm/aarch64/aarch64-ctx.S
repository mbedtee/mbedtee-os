/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * save/restore AArch64 based exception ctx
 */

#include "aarch64-ctx.h"

/* lr / x0 are saved outside, before call this func */
FUNC_START save_thread_ctx
	# struct thread_ctx

	/* save x1-x28 */
	stp	x1, x2, [x0, #16 * 1]
	stp	x3, x4, [x0, #16 * 2]
	stp	x5, x6, [x0, #16 * 3]
	stp	x7, x8, [x0, #16 * 4]
	stp	x9, x10, [x0, #16 * 5]
	stp	x11, x12, [x0, #16 * 6]
	stp	x13, x14, [x0, #16 * 7]
	stp	x15, x16, [x0, #16 * 8]
	stp	x17, x18, [x0, #16 * 9]
	stp	x19, x20, [x0, #16 * 10]
	stp	x21, x22, [x0, #16 * 11]
	stp	x23, x24, [x0, #16 * 12]
	stp	x25, x26, [x0, #16 * 13]
	stp	x27, x28, [x0, #16 * 14]

	mrs x10, contextidr_el1

	mrs x11, tpidr_el0
	mrs x12, ttbr0_el1

	mrs x13, sp_el0
	mrs x14, spsr_el1

	mrs x15, tpidrro_el0
	mrs	x9, elr_el1

	/* save x29/contextidr_el1 */
	stp	x29, x10, [x0, #16 * 15]

	/* save tpidr_el0 and ttbr0_el1 */
	stp	x11, x12, [x0, #16 * 16]

	/* save sp and spsr */
	stp	x13, x14, [x0, #16 * 17]

	/* save tpidrro_el0 and pc */
	stp	x15, x9, [x0, #16 * 18]

	msr spsel, #0
	isb

	mov sp, x0
	ret
FUNC_END save_thread_ctx

/* lr / x0 are restored outside this func */
FUNC_START restore_thread_ctx
	# struct thread_ctx

	msr spsel, #1

	/* restore the x29 and contextidr_el1 */
	ldp	x29, x9, [x0, #16 * 15]
	msr contextidr_el1, x9

	/* restore tpidr_el0 and ttbr0_el1 */
	ldp	x10, x11, [x0, #16 * 16]
	msr tpidr_el0, x10
	msr ttbr0_el1, x11

	/* restore sp and spsr */
	ldp	x12, x13, [x0, #16 * 17]
	msr sp_el0, x12
	msr spsr_el1, x13

	/* restore tpidrro_el0 and pc */
	ldp	x14, x15, [x0, #16 * 18]
	msr tpidrro_el0, x14
	msr elr_el1, x15
	isb

	/* restore sp_el1 for interrupt/exception */
	prepare_irq_ksp x14

	/* restore the x1 ~ x28 */
	ldp	x1, x2, [x0, #16 * 1]
	ldp	x3, x4, [x0, #16 * 2]
	ldp	x5, x6, [x0, #16 * 3]
	ldp	x7, x8, [x0, #16 * 4]
	ldp	x9, x10, [x0, #16 * 5]
	ldp	x11, x12, [x0, #16 * 6]
	ldp	x13, x14, [x0, #16 * 7]
	ldp	x15, x16, [x0, #16 * 8]
	ldp	x17, x18, [x0, #16 * 9]
	ldp	x19, x20, [x0, #16 * 10]
	ldp	x21, x22, [x0, #16 * 11]
	ldp	x23, x24, [x0, #16 * 12]
	ldp	x25, x26, [x0, #16 * 13]
	ldp	x27, x28, [x0, #16 * 14]

	ret
FUNC_END restore_thread_ctx

/*
 * __save_fpu_simd(void *fpu_area)
 *
 * Save FP/SIMD state (fpsr, fpcr, Q0-Q31) to memory.
 * x0 - pointer to the fpsr field (start of FPU area).
 */
FUNC_START __save_fpu_simd
	stp	q0, q1, [x0, #16 * 1]
	stp	q2, q3, [x0, #16 * 3]
	stp	q4, q5, [x0, #16 * 5]
	stp	q6, q7, [x0, #16 * 7]
	stp	q8, q9, [x0, #16 * 9]
	stp	q10, q11, [x0, #16 * 11]
	stp	q12, q13, [x0, #16 * 13]
	stp	q14, q15, [x0, #16 * 15]
	stp	q16, q17, [x0, #16 * 17]
	stp	q18, q19, [x0, #16 * 19]
	stp	q20, q21, [x0, #16 * 21]
	stp	q22, q23, [x0, #16 * 23]
	stp	q24, q25, [x0, #16 * 25]
	stp	q26, q27, [x0, #16 * 27]
	stp	q28, q29, [x0, #16 * 29]
	stp	q30, q31, [x0, #16 * 31]
	mrs	x10, fpsr
	mrs	x11, fpcr
	stp	x10, x11, [x0]
	dsb ish
	isb
	ret
FUNC_END __save_fpu_simd

/*
 * __restore_fpu_simd(void *fpu_area)
 *
 * Restore FP/SIMD state (fpsr, fpcr, Q0-Q31) from memory.
 * x0 - pointer to the fpsr field (start of FPU area).
 */
FUNC_START __restore_fpu_simd
	/*
	 * load Q registers first, then FPSR, then FPCR.
	 * (with compare-before-write to avoid flushing the FPU
	 * pipeline on in-order cores like A53/A35/A57/A72/A73).
	 */
	ldp	q0, q1, [x0, #16 * 1]
	ldp	q2, q3, [x0, #16 * 3]
	ldp	q4, q5, [x0, #16 * 5]
	ldp	q6, q7, [x0, #16 * 7]
	ldp	q8, q9, [x0, #16 * 9]
	ldp	q10, q11, [x0, #16 * 11]
	ldp	q12, q13, [x0, #16 * 13]
	ldp	q14, q15, [x0, #16 * 15]
	ldp	q16, q17, [x0, #16 * 17]
	ldp	q18, q19, [x0, #16 * 19]
	ldp	q20, q21, [x0, #16 * 21]
	ldp	q22, q23, [x0, #16 * 23]
	ldp	q24, q25, [x0, #16 * 25]
	ldp	q26, q27, [x0, #16 * 27]
	ldp	q28, q29, [x0, #16 * 29]
	ldp	q30, q31, [x0, #16 * 31]
	ldp	x6, x7, [x0]
	msr	fpsr, x6
	/*
	 * Compare-before-write: on in-order A53/A35/A57/A72/A73 cores,
	 * a redundant msr fpcr can flush the FPU pipeline and discard
	 * in-flight load results.
	 */
	mrs	x6, fpcr
	cmp	x6, x7
	beq	1f
	msr	fpcr, x7
1:	isb
	ret
FUNC_END __restore_fpu_simd

/*
 * save_fpu_ctx(struct thread_ctx *ctx)
 *
 * Save FPU state (fpsr, fpcr, Q0-Q31) from physical
 * registers to the FPU area of struct thread_ctx.
 */
FUNC_START save_fpu_ctx
	add	x0, x0, #(GPR_CTX_SIZE)
	b	__save_fpu_simd
FUNC_END save_fpu_ctx

/*
 * restore_fpu_ctx(struct thread_ctx *ctx)
 *
 * Restore FPU state (fpsr, fpcr, Q0-Q31) from the
 * FPU area of struct thread_ctx to physical registers.
 */
FUNC_START restore_fpu_ctx
	add	x0, x0, #(GPR_CTX_SIZE)
	b	__restore_fpu_simd
FUNC_END restore_fpu_ctx

/*
 * save_fpu_ctx_eager
 *
 * Eagerly save FPU state when entering kernel.
 * If fpu_owner is set, save Q0-Q31/fpsr/fpcr to owner->sched_ctx,
 * clear fpu_owner, and enable the EL0 FPU trap.
 *
 * Called from save_thread_context / save_thread_context_el0 macros.
 */
FUNC_START save_fpu_ctx_eager
	mrs	x1, tpidr_el1
	ldr	x2, [x1, #PERCPU_FPU_OWNER]
	cbz	x2, 1f
	stp	x1, x30, [sp, #-16]!
	ldr	x0, [x2, #THREAD_SCHED_CTX]
	bl	save_fpu_ctx
	ldp	x1, x30, [sp], #16
	str	xzr, [x1, #PERCPU_FPU_OWNER]
	mov	x0, #0x130000		/* CPACR_FPEN_TRAP_EL0 */
	msr	cpacr_el1, x0
	isb
1:
	ret
FUNC_END save_fpu_ctx_eager
