/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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

	/* FP/SIMD registers */
	mrs	x10, fpsr
	mrs	x11, fpcr
	stp	x10, x11, [x0, #16 * 19]

	stp	q0, q1, [x0, #16 * 20]
	stp	q2, q3, [x0, #16 * 22]
	stp	q4, q5, [x0, #16 * 24]
	stp	q6, q7, [x0, #16 * 26]
	stp	q8, q9, [x0, #16 * 28]
	stp	q10, q11, [x0, #16 * 30]
	stp	q12, q13, [x0, #16 * 32]
	stp	q14, q15, [x0, #16 * 34]
	stp	q16, q17, [x0, #16 * 36]
	stp	q18, q19, [x0, #16 * 38]
	stp	q20, q21, [x0, #16 * 40]
	stp	q22, q23, [x0, #16 * 42]
	stp	q24, q25, [x0, #16 * 44]
	stp	q26, q27, [x0, #16 * 46]
	stp	q28, q29, [x0, #16 * 48]
	stp	q30, q31, [x0, #16 * 50]

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
	mrs x14, tpidr_el1
	ldr x15, [x14, #(PERCPU_IRQ_KSP)]
	mov sp, x15

	/* restore FP/SIMD state/ctrl */
	ldp	x14, x15, [x0, #16 * 19]
	msr	fpsr, x14
	msr	fpcr, x15
	isb

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

	/* restore FP/SIMD registers */
	ldp	q0, q1, [x0, #16 * 20]
	ldp	q2, q3, [x0, #16 * 22]
	ldp	q4, q5, [x0, #16 * 24]
	ldp	q6, q7, [x0, #16 * 26]
	ldp	q8, q9, [x0, #16 * 28]
	ldp	q10, q11, [x0, #16 * 30]
	ldp	q12, q13, [x0, #16 * 32]
	ldp	q14, q15, [x0, #16 * 34]
	ldp	q16, q17, [x0, #16 * 36]
	ldp	q18, q19, [x0, #16 * 38]
	ldp	q20, q21, [x0, #16 * 40]
	ldp	q22, q23, [x0, #16 * 42]
	ldp	q24, q25, [x0, #16 * 44]
	ldp	q26, q27, [x0, #16 * 46]
	ldp	q28, q29, [x0, #16 * 48]
	ldp	q30, q31, [x0, #16 * 50]

	ret
FUNC_END restore_thread_ctx
