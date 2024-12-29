/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * per-cpu structure
 */

#ifndef _PERCPU_H
#define _PERCPU_H

#include <ctx.h>
#include <cpu.h>
#include <init.h>
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/cdefs.h>
#include <generated/autoconf.h>

/*
 * At least aligned to CACHE_LINE size (64 bytes),
 * otherwise the CACHE_LINE uses by 2 CPU will be corrupted
 * during the MMU/SMP unready stage.
 */
struct percpu {
	/* cpu ID */
	short id;
	/* in interrupt context or not */
	short in_interrupt;

	/* cpu mpid */
	unsigned long mpid;

	/* 'common_stack' for interrupt/exception */
	void *stack;
	/* current user thread's kernel stack */
	void *thread_ksp;

	/* current svc, fiq or smc calls' ctx regs */
	struct thread_ctx *int_ctx;

#ifdef CONFIG_REE_THREAD
	/* indicate current sched entity is for REE */
	int is_ns;
	/* secure world (TEE) context - exclude the thread ctx */
	struct percpu_ctx ctx;
	/* non-secure world (REE) context - exclude the hread ctx  */
	struct percpu_ctx rctx;
#else
	/* secure world (TEE) context - thread + cpu ctx */
	struct thread_ctx_el3 ctx;
	/* non-secure world (REE) - thread + cpu ctx */
	struct thread_ctx_el3 rctx;
#endif
} __aligned(64);

extern struct percpu percpu_dt[CONFIG_NR_CPUS];

int __init cpu_data_init(void);

void percpu_info(void);

static __always_inline struct percpu *percpu_data(void)
{
	struct percpu *pc = NULL;

	assert(irqs_disabled());

	asm("mrc p15, 0, %0, c13, c0, 4" : "=r" (pc));

	return pc;
}

#define thiscpu percpu_data()

static __always_inline unsigned long mpid_of(int cpu)
{
	return percpu_dt[cpu].mpid;
}

static __always_inline int cpuid_of(unsigned long mpid)
{
	int cpu = 0;

	for (cpu = 0; cpu < CONFIG_NR_CPUS; cpu++) {
		if (mpid_of(cpu) == mpid)
			return cpu;
	}

	return -1;
}

static __always_inline int percpu_id(void)
{
	return thiscpu->id;
}

static __always_inline unsigned long percpu_mpid(void)
{
	return thiscpu->mpid;
}

#endif
