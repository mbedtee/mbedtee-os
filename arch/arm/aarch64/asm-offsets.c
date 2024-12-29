// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch64 ASM offsets
 */

#include <percpu.h>
#include <pthread.h>

#define DEFINE(name, value) \
	({asm volatile("\n->" #name " %0 " #value : : "i" (value)); })

int main(void)
{
	DEFINE(PERCPU_THREAD_KSP, offsetof(struct percpu, thread_ksp));
	DEFINE(PERCPU_IRQ_KSP, offsetof(struct percpu, stack));
	DEFINE(PERCPU_DATA_SIZE, (sizeof(struct percpu)));
	DEFINE(THREAD_CTX_SIZE, (sizeof(struct thread_ctx)));
	DEFINE(PERCPU_REE_CTX, offsetof(struct percpu, rctx)); /* link to monitor */
	DEFINE(PERCPU_SMC_SGI, offsetof(struct percpu, sgi)); /* link to monitor */

	return 0;
}
