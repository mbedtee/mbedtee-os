// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * AArch32 ASM offsets
 */

#include <percpu.h>
#include <pthread.h>
#include <thread.h>

#define DEFINE(name, value) \
	({asm volatile("\n->" #name " %0 " #value : : "i" (value)); })

int main(void)
{
	DEFINE(PERCPU_TEE_CTX, offsetof(struct percpu, ctx)); /* link to monitor */
	DEFINE(PERCPU_REE_CTX, offsetof(struct percpu, rctx)); /* link to monitor */
	DEFINE(PERCPU_DATA_SIZE, (sizeof(struct percpu)));
	DEFINE(PERCPU_THREAD_KSP, offsetof(struct percpu, thread_ksp));
	DEFINE(PERCPU_IRQ_KSP, offsetof(struct percpu, stack));
	DEFINE(PERCPU_FPU_OWNER, offsetof(struct percpu, fpu_owner));
	DEFINE(THREAD_CTX_SIZE, (sizeof(struct thread_ctx)));
	DEFINE(THREAD_SCHED_CTX, offsetof(struct thread, sched_ctx));
	DEFINE(GPR_CTX_SIZE, offsetof(struct thread_ctx, fpscr));
	DEFINE(FPU_CTX_SIZE, sizeof(struct thread_ctx) - offsetof(struct thread_ctx, fpscr));
	DEFINE(PERCPU_CTX_VFP_SIZE, (int)(offsetof(struct percpu_ctx, cpacr) - offsetof(struct percpu_ctx, fpexc)));

	return 0;
}
