/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * save/restore MIPS32 based exception ctx
 */

#include <mips32-asm.h>

.section ".asm.text", "ax"

.set	push
.set	noat
.set	noreorder
.set	nomips16

FUNC_START save_thread_ctx
	# struct thread_ctx
	/* save RA/SP */
	sw		k1, THREAD_CTX_RA(sp)
	sw		k0, THREAD_CTX_SP(sp)
	/* save generic registers */
	sw		t7, THREAD_CTX_R15(sp)
	sw		t6, THREAD_CTX_R14(sp)
	sw		t5, THREAD_CTX_R13(sp)
	sw		t4, THREAD_CTX_R12(sp)
	sw		t3, THREAD_CTX_R11(sp)
	sw		t2, THREAD_CTX_R10(sp)
	sw		t1, THREAD_CTX_R9(sp)
	sw		t0, THREAD_CTX_R8(sp)

	mfc0	t7, C0_STATUS
	sw		a3, THREAD_CTX_R7(sp)
	sw		a2, THREAD_CTX_R6(sp)
	sw		t7, THREAD_CTX_STAT(sp)

	mfc0	t4, C0_CONTEXT, 2
	mfc0	t6, C0_CAUSE
	sw		a1, THREAD_CTX_R5(sp)
	sw		a0, THREAD_CTX_R4(sp)
	sw		t6, THREAD_CTX_CAUSE(sp)
	sw		t4, THREAD_CTX_UL(sp)

	mfc0	t5, C0_EPC
	sw		v1, THREAD_CTX_R3(sp)
	sw		v0, THREAD_CTX_R2(sp)
	sw		t5, THREAD_CTX_PC(sp)

	mfhi	t4
	sw		AT, THREAD_CTX_R1(sp)
	sw		$0, THREAD_CTX_R0(sp)
	sw		t4, THREAD_CTX_HI(sp)
	mflo	t3
	sw		s8, THREAD_CTX_R30(sp)
	sw		gp, THREAD_CTX_GP(sp)
	sw		t3, THREAD_CTX_LO(sp)

	sw		t9, THREAD_CTX_R25(sp)
	sw		t8, THREAD_CTX_R24(sp)
	sw		s7, THREAD_CTX_R23(sp)
	sw		s6, THREAD_CTX_R22(sp)
	sw		s5, THREAD_CTX_R21(sp)
	sw		s4, THREAD_CTX_R20(sp)
	sw		s3, THREAD_CTX_R19(sp)
	sw		s2, THREAD_CTX_R18(sp)
	sw		s1, THREAD_CTX_R17(sp)
	sw		s0, THREAD_CTX_R16(sp)

	jr		ra
	move	a0, sp
FUNC_END save_thread_ctx

FUNC_START restore_thread_ctx
	# struct thread_ctx
	/* restore generic registers */
	lw		t7, THREAD_CTX_R15(sp)
	lw		t6, THREAD_CTX_R14(sp)
	lw		t5, THREAD_CTX_R13(sp)
	lw		t4, THREAD_CTX_R12(sp)
	lw		t3, THREAD_CTX_R11(sp)
	lw		t2, THREAD_CTX_R10(sp)
	lw		t1, THREAD_CTX_R9(sp)
	lw		t0, THREAD_CTX_R8(sp)

	lw		k0, THREAD_CTX_LO(sp)
	mtlo	k0

	lw		k1, THREAD_CTX_HI(sp)
	mthi	k1

	lw		a3, THREAD_CTX_R7(sp)
	lw		a2, THREAD_CTX_R6(sp)
	lw		a1, THREAD_CTX_R5(sp)
	lw		a0, THREAD_CTX_R4(sp)

	/* restore PC */
	lw		t8, THREAD_CTX_PC(sp)
	mtc0	t8, C0_EPC

	/* restore userlocal */
	lw		k0, THREAD_CTX_UL(sp)
	mtc0	k0, C0_CONTEXT, 2

	lw		v1, THREAD_CTX_R3(sp)
	lw		v0, THREAD_CTX_R2(sp)
	lw		AT, THREAD_CTX_R1(sp)

	lw		s8, THREAD_CTX_R30(sp)
	lw		gp, THREAD_CTX_GP(sp)

	lw		s7, THREAD_CTX_R23(sp)
	lw		s6, THREAD_CTX_R22(sp)
	lw		s5, THREAD_CTX_R21(sp)

	lw		s4, THREAD_CTX_R20(sp)
	lw		s3, THREAD_CTX_R19(sp)
	lw		s2, THREAD_CTX_R18(sp)
	lw		s1, THREAD_CTX_R17(sp)
	lw		s0, THREAD_CTX_R16(sp)
	lw		t9, THREAD_CTX_R25(sp)
	lw		t8, THREAD_CTX_R24(sp)

	/* restore ASID */
	percpu_asid k0
	mtc0	k0, C0_TLBHI

	/* restore stat */
	lw		k1, THREAD_CTX_STAT(sp)
	mtc0	k1, C0_STATUS
	ehb

	/* restore RA */
	move	k0, ra
	lw		ra, THREAD_CTX_RA(sp)

	/* restore SP, ret */
	jr		k0
	lw		sp, THREAD_CTX_SP(sp)
FUNC_END restore_thread_ctx

#if defined(CONFIG_FPU)

/*
 * save_fpu_ctx(struct thread_ctx *ctx)
 *
 * Save CP1/FPU state (FCSR + f0/f1..f30/f31 as 16 doubles)
 * from physical registers to the FPU area of struct thread_ctx.
 * a0 - pointer to struct thread_ctx (sched->regs)
 *
 * Temporarily enables CP1 (CU1) in Status to access FP registers,
 * then disable CP1 (CU1) - kernel always run with CU1 disabled.
 */
FUNC_START save_fpu_ctx
	.set	push
	.set	mips32r2
	.set	hardfloat

	/* enable CP1 access (CU1) while saving */
	mfc0	t1, C0_STATUS
	lui		t6, %hi(STAT_CU1)
	nor		t5, t6, zero
	and		t5, t5, t1 /* t5 - disable CP1 (CU1) */
	or		t6, t6, t1 /* t6 - enable CP1 (CU1) */
	mtc0	t6, C0_STATUS
	ehb

	/* save FCSR at GPR_CTX_SIZE(a0) */
	cfc1	t0, $31
	sw	t0, GPR_CTX_SIZE(a0)

	/* save f0/f1..f30/f31 as 16 doubles starting at GPR_CTX_SIZE+8(a0) */
	addiu	a1, a0, GPR_CTX_SIZE + 8
	sdc1	$f0,  0(a1)
	sdc1	$f2,  8(a1)
	sdc1	$f4,  16(a1)
	sdc1	$f6,  24(a1)
	sdc1	$f8,  32(a1)
	sdc1	$f10, 40(a1)
	sdc1	$f12, 48(a1)
	sdc1	$f14, 56(a1)
	sdc1	$f16, 64(a1)
	sdc1	$f18, 72(a1)
	sdc1	$f20, 80(a1)
	sdc1	$f22, 88(a1)
	sdc1	$f24, 96(a1)
	sdc1	$f26, 104(a1)
	sdc1	$f28, 112(a1)
	sdc1	$f30, 120(a1)

	/* disable CP1 (CU1) */
	mtc0	t5, C0_STATUS
	ehb

	.set	pop
	jr		ra
	nop
FUNC_END save_fpu_ctx

/*
 * restore_fpu_ctx(struct thread_ctx *ctx)
 *
 * Restore CP1/FPU state (FCSR + f0/f1..f30/f31 as 16 doubles)
 * from the FPU area of struct thread_ctx to physical registers.
 * a0 - pointer to struct thread_ctx (sched->regs)
 *
 * Temporarily enables CP1 (CU1) in Status to access FP registers.
 */
FUNC_START restore_fpu_ctx
	.set	push
	.set	mips32r2
	.set	hardfloat

	/* enable CP1 access (CU1) while restoring */
	mfc0	t1, C0_STATUS
	lui		t0, %hi(STAT_CU1)
	or		t0, t1, t0
	mtc0	t0, C0_STATUS
	ehb

	/* restore f0/f1..f30/f31 as 16 doubles */
	addiu	a1, a0, GPR_CTX_SIZE + 8
	ldc1	$f0,  0(a1)
	ldc1	$f2,  8(a1)
	ldc1	$f4,  16(a1)
	ldc1	$f6,  24(a1)
	ldc1	$f8,  32(a1)
	ldc1	$f10, 40(a1)
	ldc1	$f12, 48(a1)
	ldc1	$f14, 56(a1)
	ldc1	$f16, 64(a1)
	ldc1	$f18, 72(a1)
	ldc1	$f20, 80(a1)
	ldc1	$f22, 88(a1)
	ldc1	$f24, 96(a1)
	ldc1	$f26, 104(a1)
	ldc1	$f28, 112(a1)
	ldc1	$f30, 120(a1)

	/* restore FCSR */
	lw		t0, GPR_CTX_SIZE(a0)
	ctc1	t0, $31

	/* restore original Status */
	mtc0	t1, C0_STATUS
	ehb

	.set	pop
	jr		ra
	nop
FUNC_END restore_fpu_ctx

/*
 * save_fpu_ctx_eager
 *
 * Eagerly save FPU state on exception/interrupt entry.
 * If fpu_owner is set, save f0-f31/FCSR to fpu_owner->sched_ctx,
 * clear fpu_owner, and clear CU1 from the exception frame's stat
 * so that the thread traps on the next FPU access.
 *
 * Called from save_thread_context macro (sp = exception frame top).
 * save_fpu_ctx only clobbers t0, t1, t5, t6, a0, a1.
 */
FUNC_START save_fpu_ctx_eager
	la		t3, percpu_dt
	lw		t1, PERCPU_FPU_OWNER(t3)
	beqz	t1, 1f
	nop

	move	t4, ra					/* save own LR */
	move	t2, a0					/* save a0 (exception frame ptr) */
	lw		a0, THREAD_SCHED_CTX(t1)	/* a0 = fpu_owner->sched_ctx */
	bal		save_fpu_ctx
	nop
	move	a0, t2					/* restore a0 */

	sw		zero, PERCPU_FPU_OWNER(t3)	/* fpu_owner = NULL */

	/* clear CU1 from exception frame stat so thread traps on next FPU use */
	lw		t0, THREAD_CTX_STAT(sp)
	lui		t5, %hi(STAT_CU1)
	nor		t5, t5, zero
	and		t0, t0, t5
	sw		t0, THREAD_CTX_STAT(sp)

	jr		t4
	nop
1:
	jr		ra
	nop
FUNC_END save_fpu_ctx_eager

#endif /* CONFIG_FPU */

.set	pop
