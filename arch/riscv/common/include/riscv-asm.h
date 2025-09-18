/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>
 * ASM macros for RISCV
 */

#ifndef _RISCV_ASM_MACROS_H
#define _RISCV_ASM_MACROS_H

#include <cpu.h>
#include <map.h>
#include <cacheops.h>

#include <generated/autoconf.h>
#include <generated/asm-offsets.h>

.macro FUNC_START name
.option norelax
	.balign 4
	.global \name
	.type \name, %function
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
	/*
	 * Clear mstatush to ensure MBE/SBE (big-endian bits) are zero,
	 * guaranteeing little-endian operation before configuring menvcfg.
	 */
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

/*
 * Detect ISA extension features by checking if menvcfg's
 * STCE (Sstc), PBMTE (Svpbmt) and CBCFE (Zicbom) bits stuck
 * after set_menvcfg. Results are stored as a unified bitmap
 * in __riscv_features for extensible feature detection.
 *
 * Must be called after set_menvcfg.
 */
.macro detect_riscv_features
	la t3, __riscv_features
	LDR t4, (t3)
	csrr a1, mtvec
	la a2, 55f
	csrw mtvec, a2
#if defined(CONFIG_64BIT)
	csrr t2, menvcfg
	/* PBMTE (bit 62) -> RISCV_FEAT_SVPBMT */
	slli t0, t2, 1
	srli t0, t0, 63
	or t4, t4, t0
	/* CBCFE (bit 6) -> RISCV_FEAT_ZICBOM */
	srli t0, t2, 6
	andi t0, t0, 1
	slli t0, t0, 1
	or t4, t4, t0
	/* STCE (bit 63) -> RISCV_FEAT_SSTC */
	srli t0, t2, 63
	slli t0, t0, 2
	or t4, t4, t0
#else
	csrr t2, menvcfgh
	/* PBMTE (bit 30 of menvcfgh) -> RISCV_FEAT_SVPBMT */
	srli t0, t2, 30
	andi t0, t0, 1
	or t4, t4, t0
	/* STCE (bit 31 of menvcfgh) -> RISCV_FEAT_SSTC */
	srli t0, t2, 31
	slli t0, t0, 2
	or t4, t4, t0
	csrr t2, menvcfg
	/* CBCFE (bit 6) -> RISCV_FEAT_ZICBOM */
	srli t0, t2, 6
	andi t0, t0, 1
	slli t0, t0, 1
	or t4, t4, t0
#endif
	STR t4, (t3)
	.align 2
55:	csrw mtvec, a1
.endm

/*
 * Andes vendor-specific cache initialization.
 * Detect Andes CPU by mvendorid (0x31e), invalidate L1 I/D caches
 * via CCTL, enable caches with CCTL S/U-mode access.
 * Set RISCV_FEAT_ANDES in __riscv_features.
 *
 * Andes CCTL CSRs:
 *   mcache_ctl (0x7ca) - Cache control register
 *   mcctlcommand (0x7cc) - CCTL command register
 *
 * Must be called after detect_riscv_features.
 */
.macro andes_cache_init
	csrr a1, mtvec
	csrr t0, mvendorid
	li t1, 0x31e /* Andes mvendorid */
	bne t0, t1, 66f

	/* Invalidate L1 I-cache and D-cache via CCTL */
	la a2, 66f
	csrw mtvec, a2

	li t0, CCTL_L1I_INVAL_ALL
	csrw 0x7cc, t0
	li t0, CCTL_L1D_INVAL_ALL
	csrw 0x7cc, t0

	/*
	 * Enable I-cache (bit 0), D-cache (bit 1),
	 * CCTL S/U-mode access (bit 8)
	 */
	csrr t0, 0x7ca
	li t1, (1 << 0) | (1 << 1) | (1 << 8)
	or t0, t0, t1
	csrw 0x7ca, t0

	/* Set RISCV_FEAT_ANDES in __riscv_features */
	la t3, __riscv_features
	LDR t4, (t3)
	li t0, (1 << 8) /* RISCV_FEAT_ANDES */
	or t4, t4, t0
	STR t4, (t3)

	.align 2
66:	csrw mtvec, a1
.endm

/*
 * T-Head vendor-specific cache initialization.
 * Detect T-Head CPU by mvendorid (0x5b7), enable caches via
 * mhcr (0x7c1), and set RISCV_FEAT_THEAD in __riscv_features
 * for xtheadcmo cache operations.
 *
 * T-Head CSRs:
 *   mhcr (0x7c1) - Machine Hardware Config Register
 *     bit 0: IE - I-cache enable
 *     bit 1: DE - D-cache enable
 *     bit 2: WA - D-cache write-allocate enable
 *     bit 3: WB - D-cache write-back enable
 *     bit 4: RS - Return stack enable
 *     bit 5: BPE - Branch prediction enable
 *     bit 6: BTB - Branch target buffer enable
 *
 * Must be called after detect_riscv_features.
 */
.macro thead_cache_init
	csrr a1, mtvec
	csrr t0, mvendorid
	li t1, 0x5b7 /* T-Head mvendorid */
	bne t0, t1, 77f

	la a2, 77f
	csrw mtvec, a2

	/*
	 * Invalidate L1 I-cache and D-cache before enabling.
	 * Cache SRAMs may contain stale data after power-on or
	 * warm reset; enabling without invalidation first could
	 * cause the CPU to use garbage cache entries.
	 */
	.long 0x0100000b /* th.icache.iall */
	.long 0x0020000b /* th.dcache.iall */
	.long 0x0190000b /* th.sync.s */

	/* Enable caches via mhcr (0x7c1) if not already enabled */
	csrr t0, 0x7c1
	li t1, (1 << 0) | (1 << 1) /* IE | DE */
	or t0, t0, t1
	csrw 0x7c1, t0

	csrw mtvec, a1

	/* Set RISCV_FEAT_THEAD in __riscv_features */
	la t3, __riscv_features
	LDR t4, (t3)
	li t0, (1 << 9) /* RISCV_FEAT_THEAD */
	or t4, t4, t0
	STR t4, (t3)

	.align 2
77:	csrw mtvec, a1
.endm

/*
 * Set a permissive PMP entry (RWX for all addresses, not locked)
 * to allow S-mode execution. Fine-grained PMP will be configured
 * later from S-mode via ecall after DTS is available.
 */
.macro set_pmp
	li t1, -1
	csrw pmpaddr0, t1
	li t2, 0xf /* NAPOT | RWX (not locked) */
	csrw pmpcfg0, t2
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
