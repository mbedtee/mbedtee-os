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
#include <stdbool.h>
#include <assert.h>
#include <sys/cdefs.h>
#include <generated/autoconf.h>

struct percpu {
	/* cpu ID */
	short id;
	/* in interrupt context or not */
	short in_interrupt;

	/* cpu hartid */
	unsigned long hartid;

	/* 'common_stack' for interrupt/exception */
	void *stack;
	/* current thread's kernel stack */
	void *thread_ksp;

	/* current thread on executing */
	void *current_thread;

	/* current svc / irq ctx regs */
	struct thread_ctx *int_ctx;

	/* current fpu context regs ptr */
	struct thread_ctx *fctx;

	/*
	 * similar as mips K0/K1 registers,
	 * temporary use when enter exception
	 */
	unsigned long k0k1[2];
} __aligned(64);

extern struct percpu percpu_dt[CONFIG_NR_CPUS];

int __init cpu_data_init(void);

void percpu_info(void);

static __always_inline struct percpu *percpu_data(void)
{
	struct percpu *pc = NULL;

	assert(irqs_disabled());

#if defined(CONFIG_RISCV_S_MODE)
	asm("csrr %0, sscratch" : "=r" (pc));
#else
	asm("csrr %0, mscratch" : "=r" (pc));
#endif

	return pc;
}

#define thiscpu percpu_data()

static __always_inline unsigned long hartid_of(int cpu)
{
	return percpu_dt[cpu].hartid;
}

static __always_inline int cpuid_of(unsigned long hartid)
{
	int cpu = 0;

	for (cpu = 0; cpu < CONFIG_NR_CPUS; cpu++) {
		if (hartid_of(cpu) == hartid)
			return cpu;
	}

	return -1;
}

static __always_inline int percpu_id(void)
{
	return thiscpu->id;
}

static __always_inline int percpu_hartid(void)
{
	return thiscpu->hartid;
}

#endif
