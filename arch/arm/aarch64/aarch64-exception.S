/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * exception vectors for AArch64 based
 */

#include "aarch64-ctx.h"

.align 11
.global exception_vectors
exception_vectors:
/* Current EL with SP0 */
synchronous_el1_sp0:
	save_thread_context
	bl exception_handler
 	b exception_return
	.align 7
irq_el1_sp0:
	save_thread_context
	bl irq_handler
 	b exception_return
	.align 7
fiq_el1_sp0:
	b irq_el1_sp0
	b .
	.align 7
serror_el1_sp0:
	b .
 	b synchronous_el1_sp0
	.align 7

/* Current EL with SPx */
synchronous_el1_sp1:
	b .
	save_thread_context
	bl exception_handler
 	b exception_return
	.align 7
irq_el1_sp1:
	b .
	b synchronous_el1_sp1
	.align 7
fiq_el1_sp1:
	b .
	b synchronous_el1_sp1
	.align 7
serror_el1_sp1:
	b .
	b synchronous_el1_sp1
	.align 7

/* Lower EL using AArch64 */
synchronous_el0:
	save_thread_context_el0
	bl exception_handler
	mov sp, x0 /* x0 might be changed during syscall */
 	b exception_return
	.align 7
irq_el0:
	save_thread_context
	bl irq_handler
 	b exception_return
	.align 7
fiq_el0:
	b irq_el0
	b .
	.align 7
serror_el0:
	b .
	b synchronous_el0
	.align 7

/* Lower EL using AArch32 */
synchronous_el0_aarch32:
	b .
	save_thread_context_el0
	bl exception_handler
 	b exception_return
	.align 7
irq_el0_aarch32:
	b .
	b synchronous_el0_aarch32
	.align 7
fiq_el0_aarch32:
	b .
	b synchronous_el0_aarch32
	.align 7
serror_el0_aarch32:
	b .
	b synchronous_el0_aarch32
	.align 7

exception_return:
	restore_thread_context
	clrex
	eret

/*
 * schedule routine (yield to other thread).
 * Must not use the current thread's stack
 */
FUNC_START schedule
	mrs x3, daif
	msr daifset, #15
	isb
	orr x3, x3, #(SPSR_MODE_EL1T)
	msr spsr_el1, x3
	msr elr_el1, lr
	msr spsel, #1 /* using IRQ_KSP stack */
	isb

	save_thread_context
	bl sched_exec
 	b exception_return
FUNC_END schedule
