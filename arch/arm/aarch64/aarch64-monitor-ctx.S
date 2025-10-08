/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * EL3 - Secure Monitor Context handling
 * TEE/REE world context switching
 */

#include "aarch64-monitor.h"

/* the lr / x0 are saved before this func */
.type save_percpu_ctx, %function
.global save_percpu_ctx
save_percpu_ctx:
	# struct thread_ctx_el3

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

	/* save x29/contextidr_el1 */
	stp	x29, x10, [x0, #16 * 15]

	mrs x11, tpidr_el0
	mrs x12, ttbr0_el1
	mrs x13, sp_el0
	mrs x14, spsr_el3

	/* save tpidr_el0 and ttbr0_el1 */
	stp	x11, x12, [x0, #16 * 16]
	/* save sp and spsr */
	stp	x13, x14, [x0, #16 * 17]

	mrs x11, tpidrro_el0
	mrs	x12, elr_el3
	mrs x13, spsr_el1
	mrs	x14, elr_el1

	/* save tpidrro_el0 and pc */
	stp	x11, x12, [x0, #16 * 18]
	/* save spsr_el1 and elr_el1 */
	stp	x13, x14, [x0, #16 * 19]

	/* save s/ns world per-cpu registers */
	mrs x10, vbar_el1
	mrs	x11, ttbr1_el1
	mrs x12, tcr_el1
	mrs	x13, mair_el1
	mrs	x14, sctlr_el1
	mrs x15, sp_el1
	stp	x10, x11, [x0, #16 * 20]
	stp	x12, x13, [x0, #16 * 21]
	stp	x14, x15, [x0, #16 * 22]

	mrs x10, esr_el1
	mrs	x11, far_el1
	mrs x12, cpacr_el1
	mrs	x13, csselr_el1
	mrs	x14, par_el1
	mrs x15, tpidr_el1
	stp	x10, x11, [x0, #16 * 23]
	stp	x12, x13, [x0, #16 * 24]
	stp	x14, x15, [x0, #16 * 25]

	mrs x10, cntkctl_el1
	mrs	x11, cntp_ctl_el0
	mrs x12, cntp_cval_el0
	mrs	x13, cntv_ctl_el0
	mrs	x14, cntv_cval_el0
	mrs x15, actlr_el1
	stp	x10, x11, [x0, #16 * 26]
	stp	x12, x13, [x0, #16 * 27]
	stp	x14, x15, [x0, #16 * 28]

	mrs x10, afsr0_el1
	mrs x11, afsr1_el1
	stp	x10, x11, [x0, #16 * 29]

	/* FP/SIMD registers */
	mrs	x10, fpsr
	mrs	x11, fpcr
	stp	x10, x11, [x0, #16 * 30]

	stp	q0, q1, [x0, #16 * 31]
	stp	q2, q3, [x0, #16 * 33]
	stp	q4, q5, [x0, #16 * 35]
	stp	q6, q7, [x0, #16 * 37]
	stp	q8, q9, [x0, #16 * 39]
	stp	q10, q11, [x0, #16 * 41]
	stp	q12, q13, [x0, #16 * 43]
	stp	q14, q15, [x0, #16 * 45]
	stp	q16, q17, [x0, #16 * 47]
	stp	q18, q19, [x0, #16 * 49]
	stp	q20, q21, [x0, #16 * 51]
	stp	q22, q23, [x0, #16 * 53]
	stp	q24, q25, [x0, #16 * 55]
	stp	q26, q27, [x0, #16 * 57]
	stp	q28, q29, [x0, #16 * 59]
	stp	q30, q31, [x0, #16 * 61]

	ret
.size save_percpu_ctx, .-save_percpu_ctx

/* the lr / x0 are restored outside this func */
.type restore_percpu_ctx, %function
.global restore_percpu_ctx
restore_percpu_ctx:

	# struct thread_ctx_el3

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
	msr spsr_el3, x13

	/* restore tpidrro_el0 and pc */
	ldp	x14, x15, [x0, #16 * 18]
	msr tpidrro_el0, x14
	msr elr_el3, x15

	/* restore spsr_el1 and elr_el1 */
	ldp	x12, x13, [x0, #16 * 19]
	msr spsr_el1, x12
	msr elr_el1, x13

	/* save s/ns world per-cpu registers */
	ldp	x10, x11, [x0, #16 * 20]
	ldp	x12, x13, [x0, #16 * 21]
	ldp	x14, x15, [x0, #16 * 22]
	msr vbar_el1, x10
	msr	ttbr1_el1, x11
	msr tcr_el1, x12
	msr	mair_el1, x13
	msr	sctlr_el1, x14
	msr sp_el1, x15

	ldp	x10, x11, [x0, #16 * 23]
	ldp	x12, x13, [x0, #16 * 24]
	ldp	x14, x15, [x0, #16 * 25]
	msr esr_el1, x10
	msr	far_el1, x11
	msr cpacr_el1, x12
	msr	csselr_el1, x13
	msr	par_el1, x14
	msr tpidr_el1, x15

	ldp	x10, x11, [x0, #16 * 26]
	ldp	x12, x13, [x0, #16 * 27]
	ldp	x14, x15, [x0, #16 * 28]
	msr cntkctl_el1, x10
	msr	cntp_ctl_el0, x11
	msr cntp_cval_el0, x12
	msr	cntv_ctl_el0, x13
	msr	cntv_cval_el0, x14
	msr actlr_el1, x15

	ldp	x11, x12, [x0, #16 * 29]
	msr	afsr0_el1, x11
	msr	afsr1_el1, x12

	/* restore FP/SIMD state/ctrl */
	ldp	x14, x15, [x0, #16 * 30]
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
	ldp	q0, q1, [x0, #16 * 31]
	ldp	q2, q3, [x0, #16 * 33]
	ldp	q4, q5, [x0, #16 * 35]
	ldp	q6, q7, [x0, #16 * 37]
	ldp	q8, q9, [x0, #16 * 39]
	ldp	q10, q11, [x0, #16 * 41]
	ldp	q12, q13, [x0, #16 * 43]
	ldp	q14, q15, [x0, #16 * 45]
	ldp	q16, q17, [x0, #16 * 47]
	ldp	q18, q19, [x0, #16 * 49]
	ldp	q20, q21, [x0, #16 * 51]
	ldp	q22, q23, [x0, #16 * 53]
	ldp	q24, q25, [x0, #16 * 55]
	ldp	q26, q27, [x0, #16 * 57]
	ldp	q28, q29, [x0, #16 * 59]
	ldp	q30, q31, [x0, #16 * 61]

	ret
.size restore_percpu_ctx, .-restore_percpu_ctx
