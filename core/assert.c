// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Kernel assert_func
 */

#include <printk.h>
#include <percpu.h>
#include <thread.h>
#include <assert.h>

#if defined(CONFIG_UART)
#define ASSERT_SERIAL_ONLY
extern void uart_early_puts(const char *str, size_t cnt);
#endif

/* for kernel */
void assert_func(int line, const char *func, const char *expr)
{
	char tracestr[200];

	local_irq_disable();

	snprintf(tracestr, sizeof(tracestr),
			"\n!!oops-%s@CPU%d %s() L%d expr: %s\n",
			current->name, sched_getcpu(), func, line, expr);

#if defined(ASSERT_SERIAL_ONLY)
	uart_early_puts(tracestr, strlen(tracestr));
#else
	printk_raw(tracestr, strlen(tracestr));
#endif

	backtrace();

	deadloop();
}

