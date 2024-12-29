/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ASM macros for RISCV
 */

#ifndef _RISCV_ASM_MACROS_H
#define _RISCV_ASM_MACROS_H

#include <cpu.h>

#include <generated/autoconf.h>
#include <generated/asm-offsets.h>

.macro FUNC_START name
.option norelax
	.balign 4
	.global \name
	.type \name, % function
\name :
.endm

.macro FUNC_END name
	.size \name, . -\name
.endm

#if __riscv_flen == 64
#define FLDR fld
#define FSTR fsd
#elif __riscv_flen == 32
#define FLDR flw
#define FSTR fsw
#endif

#if defined(CONFIG_64BIT)
#define LDR ld
#define STR sd
#else
#define LDR lw
#define STR sw
#endif

/* Set the global pointer */
.macro set_gp
.option norelax
	la gp, __global_pointer$
.endm

.macro set_tp
	csrr tp, CSR_SCRATCH
	LDR tp, PERCPU_CURRENT_THREAD(tp)
.endm

/*
 * save the thread context
 */
.macro save_thread_context
	csrrw t6, CSR_SCRATCH, t6

	STR t0, PERCPU_K0(t6)
	STR t1, PERCPU_K1(t6)

	/* came from interrupt or exception ? */
	csrr t0, CSR_CAUSE
	li t1, 1 << (__riscv_xlen - 1)
	and t1, t0, t1
	LDR t0, PERCPU_IRQ_KSP(t6)/* use IRQ original sp if from interrupt */
	bnez t1, 1f

	/* exception was came from user or kernel space ? */
	csrr t0, CSR_STATUS
	li t1, SR_PP
	and t1, t0, t1

	mv t0, sp /* continues on the original sp if from kernel */
	bnez t1, 1f /* bnez: from kernel */
	LDR t0, PERCPU_THREAD_KSP(t6)
1 : addi t0, t0, -THREAD_CTX_SIZE
	STR a0, THREAD_CTX_A0(t0)
	STR ra, THREAD_CTX_RA(t0)
	mv a0, t0
	LDR t0, PERCPU_K0(t6)
	LDR t1, PERCPU_K1(t6)
	csrrw t6, CSR_SCRATCH, t6

	call save_thread_ctx
	set_gp
	set_tp
	li t1, SR_FS
	csrc CSR_STATUS, t1
.endm

/*
 * 1. simulate exception
 * 2. save the thread context with IRQ SP
 */
.macro save_thread_context_sched
	csrrci a4, CSR_STATUS, SR_IE
	csrw CSR_EPC, ra

	csrr a0, CSR_SCRATCH
	LDR a0, PERCPU_IRQ_KSP(a0)
	addi a0, a0, -THREAD_CTX_SIZE

	STR ra, THREAD_CTX_RA(a0)

	call save_thread_ctx
	andi a3, a4, SR_IE
	slli a3, a3, 4
	li a2, SR_PP
	or a3, a3, a2
	li a2, ~(SR_IE | SR_PIE)
	and a4, a4, a2
	or a4, a4, a3
	STR a4, THREAD_CTX_STAT(a0)
.endm

/*
 * restore the thread context
 */
.macro restore_thread_context
	call sched_sighandle
	call restore_thread_ctx
	LDR ra, THREAD_CTX_RA(a0)
	LDR a0, THREAD_CTX_A0(a0)
.endm

#endif
