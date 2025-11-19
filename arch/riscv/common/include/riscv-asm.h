/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ASM macros for RISCV
 */

#ifndef _RISCV_ASM_MACROS_H
#define _RISCV_ASM_MACROS_H

#include <cpu.h>
#include <map.h>

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

.macro delay_asm
	li a3, 5555
2:	li a2, 5555
1:	addi a2, a2, -1
	bnez a2, 1b
	addi a3, a3, -1
	bnez a3, 2b
.endm

.macro csr_write tvec, csr, val
/* backup the exception entry */
	csrr a1, \tvec
	la a2, 11f
	csrw \tvec, a2

	li a2, \val
	csrw \csr, a2

/* resume exception entry */
	.align 2
11:	csrw \tvec, a1
.endm

.macro csr_writeable tvec, csr, val
/* backup the exception entry */
	csrr a1, \tvec
	la a2, 11f
	csrw \tvec, a2
	li a0, 0

/* a0 holds the return value */
	li a2, \val
	csrw \csr, a2
	li a0, 1

/* resume exception entry */
	.align 2
11:	csrw \tvec, a1
.endm

.macro is_readable addrreg
/* backup the s-mode exception entry */
	csrr a1, stvec
	la a2, 22f
	csrw stvec, a2

	move a2, \addrreg
	li a0, 0

/* a0 holds the return value */
	lw a2, (a2)

	li a0, 1

/* resume s-mode exception entry */
	.align 2
22:	csrw stvec, a1
.endm

.macro set_menvcfg
	/* backup the m-mode exception entry */
	csrr a1, mtvec
	/* check if the menvcfg exist or not */
	la a2, 33f
	csrw mtvec, a2

#if defined(CONFIG_64BIT)
	li a2, (1 << 63) | (1 << 62) /* STCE / PBMTE */
	or a2, a2, 0xf0  /* CBZE / CBCFE / CBIE / without-FIOM */
	csrw menvcfg, a2
#else
	csrw mstatush, zero
	li a2, (1 << 31) | (1 << 30) /* STCE / PBMTE */
	csrw menvcfgh, a2
	li a2, 0xf0  /* CBZE / CBCFE / CBIE / without-FIOM */
	csrw menvcfg, a2
#endif

	.align 2
33:	csrw mtvec, a1 /* resume m-mode exception entry */
.endm

.macro set_mstateen0
	/* backup the m-mode exception entry */
	csrr a1, mtvec
	/* check if the mstateen0 exist or not */
	la a2, 44f
	csrw mtvec, a2

#if defined(CONFIG_64BIT)
	li a2, (1 << 60) | (1 << 59) | (1 << 58)
	csrw mstateen0, a2
#else
	li a2, (1 << 28) | (1 << 27) | (1 << 26)
	csrw mstateen0h, a2
#endif

	.align 2
44:	csrw mtvec, a1 /* resume m-mode exception entry */
.endm

/* Using PMP TOR: pmpaddr[i-1] <= y < pmpaddr[i] */
.macro set_pmp
	/* pmp0cfg: 0 ~ 0x7FFFFFFF is set to RW (major for IO) */
	li t1, 0x80000000 >> 2
	csrw pmpaddr0, t1
	li t2, 1 << 3 | 1 << 7 | 3

	/* pmp1cfg: .data between 0x80000000 ~ PA_OFFSET is set to RWX and Locked */
	la t3, _start /* physical start */
	srli t1, t3, 2
	csrw pmpaddr1, t1
	li t3, 1 << 3 | 1 << 7 | 7
	slli t3, t3, 8
	or t2, t2, t3

	/* pmp2cfg: .text is set to RX and Locked */
	la t1, __TEXT_END
	srli t1, t1, 2
	csrw pmpaddr2, t1
	li t3, 1 << 3 | 1 << 7 | 5
	slli t3, t3, 16
	or t2, t2, t3

	/* pmp3cfg: .rodata is set to R and Locked */
	la t1, __RODATA_END
	srli t1, t1, 2
	csrw pmpaddr3, t1
	li t3, 1 << 3 | 1 << 7 | 1
	slli t3, t3, 24
	or t2, t2, t3

	/* pmp4cfg: others are set to RWX and Locked */
	li t1, -1
	csrw pmpaddr4, t1
#if defined(CONFIG_64BIT)
	li t3, 1 << 3 | 1 << 7 | 7
	slli t3, t3, 32
	or t2, t2, t3

	/* pmp0cfg ~ pmp4cfg @ pmpcfg0 */
	csrw pmpcfg0, t2
#else
	/* pmp0cfg ~ pmp3cfg @ pmpcfg0 */
	csrw pmpcfg0, t2

	/* pmp4cfg @ pmpcfg1 */
	li t2, 1 << 3 | 1 << 7 | 7
	csrw pmpcfg1, t2
#endif
	sfence.vma
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
