// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * AArch64 ASM offsets
 */

#include <percpu.h>
#include <pthread.h>
#include <thread.h>

#define DEFINE(name, value) \
	({asm volatile("\n->" #name " %0 " #value : : "i" (value)); })

int main(void)
{
	DEFINE(PERCPU_THREAD_KSP, offsetof(struct percpu, thread_ksp));
	DEFINE(PERCPU_IRQ_KSP, offsetof(struct percpu, stack));
	DEFINE(PERCPU_FPU_OWNER, offsetof(struct percpu, fpu_owner));
	DEFINE(PERCPU_DATA_SIZE, (sizeof(struct percpu)));
	DEFINE(THREAD_CTX_SIZE, (sizeof(struct thread_ctx)));
	DEFINE(THREAD_SCHED_CTX, offsetof(struct thread, sched_ctx));
	DEFINE(GPR_CTX_SIZE, offsetof(struct thread_ctx, fpsr));
	DEFINE(FPU_CTX_SIZE, sizeof(struct thread_ctx) - offsetof(struct thread_ctx, fpsr));
	DEFINE(GPR_CTX_EL3_SIZE, offsetof(struct thread_ctx_el3, fpsr));
	DEFINE(CPACR_EL3_OFFSET, offsetof(struct thread_ctx_el3, cpacr_el1));
	DEFINE(PERCPU_REE_CTX, offsetof(struct percpu, rctx)); /* link to monitor */
	DEFINE(PERCPU_SMC_SGI, offsetof(struct percpu, sgi)); /* link to monitor */

	return 0;
}
