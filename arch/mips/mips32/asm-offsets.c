// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Generate the MIPS32 Context related offsets
 */

#include <ctx.h>
#include <percpu.h>
#include <sys/types.h>

#define DEFINE(name, value) \
	({asm volatile("\n->" #name " %0 " #value : : "i" (value)); })

int main(void)
{
	DEFINE(THREAD_CTX_R0, offsetof(struct thread_ctx, r[0]));
	DEFINE(THREAD_CTX_R1, offsetof(struct thread_ctx, r[1]));
	DEFINE(THREAD_CTX_R2, offsetof(struct thread_ctx, r[2]));
	DEFINE(THREAD_CTX_R3, offsetof(struct thread_ctx, r[3]));
	DEFINE(THREAD_CTX_R4, offsetof(struct thread_ctx, r[4]));
	DEFINE(THREAD_CTX_R5, offsetof(struct thread_ctx, r[5]));
	DEFINE(THREAD_CTX_R6, offsetof(struct thread_ctx, r[6]));
	DEFINE(THREAD_CTX_R7, offsetof(struct thread_ctx, r[7]));
	DEFINE(THREAD_CTX_R8, offsetof(struct thread_ctx, r[8]));
	DEFINE(THREAD_CTX_R9, offsetof(struct thread_ctx, r[9]));
	DEFINE(THREAD_CTX_R10, offsetof(struct thread_ctx, r[10]));
	DEFINE(THREAD_CTX_R11, offsetof(struct thread_ctx, r[11]));
	DEFINE(THREAD_CTX_R12, offsetof(struct thread_ctx, r[12]));
	DEFINE(THREAD_CTX_R13, offsetof(struct thread_ctx, r[13]));
	DEFINE(THREAD_CTX_R14, offsetof(struct thread_ctx, r[14]));
	DEFINE(THREAD_CTX_R15, offsetof(struct thread_ctx, r[15]));
	DEFINE(THREAD_CTX_R16, offsetof(struct thread_ctx, r[16]));
	DEFINE(THREAD_CTX_R17, offsetof(struct thread_ctx, r[17]));
	DEFINE(THREAD_CTX_R18, offsetof(struct thread_ctx, r[18]));
	DEFINE(THREAD_CTX_R19, offsetof(struct thread_ctx, r[19]));
	DEFINE(THREAD_CTX_R20, offsetof(struct thread_ctx, r[20]));
	DEFINE(THREAD_CTX_R21, offsetof(struct thread_ctx, r[21]));
	DEFINE(THREAD_CTX_R22, offsetof(struct thread_ctx, r[22]));
	DEFINE(THREAD_CTX_R23, offsetof(struct thread_ctx, r[23]));
	DEFINE(THREAD_CTX_R24, offsetof(struct thread_ctx, r[24]));
	DEFINE(THREAD_CTX_R25, offsetof(struct thread_ctx, r[25]));
	DEFINE(THREAD_CTX_R26, offsetof(struct thread_ctx, r[26]));
	DEFINE(THREAD_CTX_R27, offsetof(struct thread_ctx, r[27]));
	DEFINE(THREAD_CTX_GP, offsetof(struct thread_ctx, gp));
	DEFINE(THREAD_CTX_SP, offsetof(struct thread_ctx, sp));
	DEFINE(THREAD_CTX_R30, offsetof(struct thread_ctx, r30));
	DEFINE(THREAD_CTX_RA, offsetof(struct thread_ctx, lr));

	DEFINE(THREAD_CTX_HI, offsetof(struct thread_ctx, hi));
	DEFINE(THREAD_CTX_LO, offsetof(struct thread_ctx, lo));
	DEFINE(THREAD_CTX_STAT, offsetof(struct thread_ctx, stat));
	DEFINE(THREAD_CTX_PC, offsetof(struct thread_ctx, pc));
	DEFINE(THREAD_CTX_CAUSE, offsetof(struct thread_ctx, cause));
	DEFINE(THREAD_CTX_UL, offsetof(struct thread_ctx, userlocal));

	DEFINE(THREAD_CTX_SIZE, sizeof(struct thread_ctx));

	DEFINE(PERCPU_DATA_ASID, offsetof(struct percpu, asid));
	DEFINE(PERCPU_THREAD_KSP, offsetof(struct percpu, thread_ksp));
	DEFINE(PERCPU_IRQ_KSP, offsetof(struct percpu, stack));

	return 0;
}
