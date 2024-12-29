/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * per-cpu structure
 */

#ifndef _PERCPU_H
#define _PERCPU_H

#include <ctx.h>
#include <init.h>
#include <stdbool.h>
#include <sys/cdefs.h>
#include <generated/autoconf.h>

struct percpu {
	/* cpu ID */
	short id;
	/* in interrupt context or not */
	short in_interrupt;

	/* 'common_stack' for interrupt/exception */
	void *stack;
	/* current user thread's kernel stack */
	void *thread_ksp;

	/* current thread on executing */
	void *current_thread;

	/* current ASID */
	unsigned long asid;
	/* current svc / irq ctx regs */
	struct thread_ctx *int_ctx;
};

extern struct percpu percpu_dt[CONFIG_NR_CPUS];

int __init cpu_data_init(void);

void percpu_info(void);

/*
 * currently tehre is only one core
 */
static __always_inline int percpu_id(void)
{
	return 0;
}

static __always_inline struct percpu *percpu_data(void)
{
	return &percpu_dt[percpu_id()];
}

#define thiscpu percpu_data()

#endif
