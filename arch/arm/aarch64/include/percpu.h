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
#include <stdbool.h>
#include <stddef.h>
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

	/* current svc / irq ctx regs */
	struct thread_ctx *int_ctx;

	/* share with el3 */
	void *rctx;
	unsigned long sgi;
} __aligned(64);

extern struct percpu percpu_dt[CONFIG_NR_CPUS];

int __init cpu_data_init(void);

void percpu_info(void);

static __always_inline struct percpu *percpu_data(void)
{
	struct percpu *pc = NULL;

	assert(irqs_disabled());

	asm("mrs %0, tpidr_el1" : "=r" (pc));

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
