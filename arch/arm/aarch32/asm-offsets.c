// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32 ASM offsets
 */

#include <percpu.h>
#include <pthread.h>

#define DEFINE(name, value) \
	({asm volatile("\n->" #name " %0 " #value : : "i" (value)); })

int main(void)
{
	DEFINE(PERCPU_TEE_CTX, offsetof(struct percpu, ctx)); /* link to monitor */
	DEFINE(PERCPU_REE_CTX, offsetof(struct percpu, rctx)); /* link to monitor */
	DEFINE(PERCPU_DATA_SIZE, (sizeof(struct percpu)));
	DEFINE(PERCPU_THREAD_KSP, offsetof(struct percpu, thread_ksp));
	DEFINE(PERCPU_IRQ_KSP, offsetof(struct percpu, stack));
	DEFINE(THREAD_CTX_SIZE, (sizeof(struct thread_ctx)));

#ifdef CONFIG_REE_THREAD
	DEFINE(PERCPU_NS_FLAG, offsetof(struct percpu, is_ns));
#endif

	return 0;
}
