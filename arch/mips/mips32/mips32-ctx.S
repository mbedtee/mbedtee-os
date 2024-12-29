/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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

.set	pop
