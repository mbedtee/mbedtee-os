/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * simple kernel panic
 */

#ifndef _PANIC_H
#define _PANIC_H

#include <cpu.h>
#include <percpu.h>
#include <printk.h>
#include <backtrace.h>
#include <thread_info.h>

static inline __dead2 void deadloop(void)
{
	while (1)
		;
}

#define panic(...) \
	do { \
		local_irq_disable(); \
		struct thread *__t_ = current; \
		printk("\n!!oops-%s@CPU%d %s() L%d PANIC: ", \
			__t_->name, percpu_id(), __func__, __LINE__); \
		printk(__VA_ARGS__); \
		backtrace(); \
		deadloop(); \
	} while (0)

#endif
