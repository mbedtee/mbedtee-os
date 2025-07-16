/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * simple kernel panic
 */

#ifndef _PANIC_H
#define _PANIC_H

#ifdef __cplusplus
extern "C" {
#endif

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
		printk("\n!!oops@CPU%d %s() L%d PANIC: ", \
			percpu_id(), __func__, __LINE__); \
		printk(__VA_ARGS__); \
		backtrace(); \
		deadloop(); \
	} while (0)

#ifdef __cplusplus
}
#endif
#endif
