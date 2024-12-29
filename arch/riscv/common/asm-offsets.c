// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Generate the RISCV Context related offsets
 */

#include <ctx.h>
#include <percpu.h>
#include <thread.h>

#include <sys/types.h>

#define DEFINE(name, value) \
	({asm volatile("\n->" #name " %0 " #value : : "i" (value)); })

int main(void)
{
	DEFINE(THREAD_CTX_RA, offsetof(struct thread_ctx, lr));
	DEFINE(THREAD_CTX_SP, offsetof(struct thread_ctx, sp));
	DEFINE(THREAD_CTX_GP, offsetof(struct thread_ctx, gp));
	DEFINE(THREAD_CTX_TP, offsetof(struct thread_ctx, tp));

	DEFINE(THREAD_CTX_T0, offsetof(struct thread_ctx, r[0]));
	DEFINE(THREAD_CTX_T1, offsetof(struct thread_ctx, r[1]));
	DEFINE(THREAD_CTX_T2, offsetof(struct thread_ctx, r[2]));
	DEFINE(THREAD_CTX_S0, offsetof(struct thread_ctx, r[3]));
	DEFINE(THREAD_CTX_S1, offsetof(struct thread_ctx, r[4]));
	DEFINE(THREAD_CTX_A0, offsetof(struct thread_ctx, r[5]));
	DEFINE(THREAD_CTX_A1, offsetof(struct thread_ctx, r[6]));
	DEFINE(THREAD_CTX_A2, offsetof(struct thread_ctx, r[7]));
	DEFINE(THREAD_CTX_A3, offsetof(struct thread_ctx, r[8]));
	DEFINE(THREAD_CTX_A4, offsetof(struct thread_ctx, r[9]));
	DEFINE(THREAD_CTX_A5, offsetof(struct thread_ctx, r[10]));
	DEFINE(THREAD_CTX_A6, offsetof(struct thread_ctx, r[11]));
	DEFINE(THREAD_CTX_A7, offsetof(struct thread_ctx, r[12]));
	DEFINE(THREAD_CTX_S2, offsetof(struct thread_ctx, r[13]));
	DEFINE(THREAD_CTX_S3, offsetof(struct thread_ctx, r[14]));
	DEFINE(THREAD_CTX_S4, offsetof(struct thread_ctx, r[15]));
	DEFINE(THREAD_CTX_S5, offsetof(struct thread_ctx, r[16]));
	DEFINE(THREAD_CTX_S6, offsetof(struct thread_ctx, r[17]));
	DEFINE(THREAD_CTX_S7, offsetof(struct thread_ctx, r[18]));
	DEFINE(THREAD_CTX_S8, offsetof(struct thread_ctx, r[19]));
	DEFINE(THREAD_CTX_S9, offsetof(struct thread_ctx, r[20]));
	DEFINE(THREAD_CTX_S10, offsetof(struct thread_ctx, r[21]));
	DEFINE(THREAD_CTX_S11, offsetof(struct thread_ctx, r[22]));
	DEFINE(THREAD_CTX_T3, offsetof(struct thread_ctx, r[23]));
	DEFINE(THREAD_CTX_T4, offsetof(struct thread_ctx, r[24]));
	DEFINE(THREAD_CTX_T5, offsetof(struct thread_ctx, r[25]));
	DEFINE(THREAD_CTX_T6, offsetof(struct thread_ctx, r[26]));

	DEFINE(THREAD_CTX_STAT, offsetof(struct thread_ctx, stat));
	DEFINE(THREAD_CTX_PC, offsetof(struct thread_ctx, pc));
	DEFINE(THREAD_CTX_CAUSE, offsetof(struct thread_ctx, cause));
	DEFINE(THREAD_CTX_SATP, offsetof(struct thread_ctx, satp));

	DEFINE(THREAD_CTX_SIZE, sizeof(struct thread_ctx));

	DEFINE(PERCPU_DATA_SIZE, sizeof(struct percpu));
	DEFINE(PERCPU_IRQ_KSP, offsetof(struct percpu, stack));
	DEFINE(PERCPU_THREAD_KSP, offsetof(struct percpu, thread_ksp));
	DEFINE(PERCPU_CURRENT_THREAD, offsetof(struct percpu, current_thread));
	DEFINE(PERCPU_K0, offsetof(struct percpu, k0k1[0]));
	DEFINE(PERCPU_K1, offsetof(struct percpu, k0k1[1]));

#if defined(__riscv_flen)
	DEFINE(THREAD_FPU_CTX_F0, offsetof(struct thread_ctx, f[0]));
	DEFINE(THREAD_FPU_CTX_F1, offsetof(struct thread_ctx, f[1]));
	DEFINE(THREAD_FPU_CTX_F2, offsetof(struct thread_ctx, f[2]));
	DEFINE(THREAD_FPU_CTX_F3, offsetof(struct thread_ctx, f[3]));
	DEFINE(THREAD_FPU_CTX_F4, offsetof(struct thread_ctx, f[4]));
	DEFINE(THREAD_FPU_CTX_F5, offsetof(struct thread_ctx, f[5]));
	DEFINE(THREAD_FPU_CTX_F6, offsetof(struct thread_ctx, f[6]));
	DEFINE(THREAD_FPU_CTX_F7, offsetof(struct thread_ctx, f[7]));
	DEFINE(THREAD_FPU_CTX_F8, offsetof(struct thread_ctx, f[8]));
	DEFINE(THREAD_FPU_CTX_F9, offsetof(struct thread_ctx, f[9]));
	DEFINE(THREAD_FPU_CTX_F10, offsetof(struct thread_ctx, f[10]));
	DEFINE(THREAD_FPU_CTX_F11, offsetof(struct thread_ctx, f[11]));
	DEFINE(THREAD_FPU_CTX_F12, offsetof(struct thread_ctx, f[12]));
	DEFINE(THREAD_FPU_CTX_F13, offsetof(struct thread_ctx, f[13]));
	DEFINE(THREAD_FPU_CTX_F14, offsetof(struct thread_ctx, f[14]));
	DEFINE(THREAD_FPU_CTX_F15, offsetof(struct thread_ctx, f[15]));
	DEFINE(THREAD_FPU_CTX_F16, offsetof(struct thread_ctx, f[16]));
	DEFINE(THREAD_FPU_CTX_F17, offsetof(struct thread_ctx, f[17]));
	DEFINE(THREAD_FPU_CTX_F18, offsetof(struct thread_ctx, f[18]));
	DEFINE(THREAD_FPU_CTX_F19, offsetof(struct thread_ctx, f[19]));
	DEFINE(THREAD_FPU_CTX_F20, offsetof(struct thread_ctx, f[20]));
	DEFINE(THREAD_FPU_CTX_F21, offsetof(struct thread_ctx, f[21]));
	DEFINE(THREAD_FPU_CTX_F22, offsetof(struct thread_ctx, f[22]));
	DEFINE(THREAD_FPU_CTX_F23, offsetof(struct thread_ctx, f[23]));
	DEFINE(THREAD_FPU_CTX_F24, offsetof(struct thread_ctx, f[24]));
	DEFINE(THREAD_FPU_CTX_F25, offsetof(struct thread_ctx, f[25]));
	DEFINE(THREAD_FPU_CTX_F26, offsetof(struct thread_ctx, f[26]));
	DEFINE(THREAD_FPU_CTX_F27, offsetof(struct thread_ctx, f[27]));
	DEFINE(THREAD_FPU_CTX_F28, offsetof(struct thread_ctx, f[28]));
	DEFINE(THREAD_FPU_CTX_F29, offsetof(struct thread_ctx, f[29]));
	DEFINE(THREAD_FPU_CTX_F30, offsetof(struct thread_ctx, f[30]));
	DEFINE(THREAD_FPU_CTX_F31, offsetof(struct thread_ctx, f[31]));
	DEFINE(THREAD_FPU_CTX_FCSR, offsetof(struct thread_ctx, fcsr));
#endif

	return 0;
}
