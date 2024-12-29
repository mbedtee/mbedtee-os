// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Kernel Log Trace
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <printk.h>
#include <percpu.h>
#include <thread.h>
#include <spinlock.h>
#include <trace.h>

#define TRACE_SIZE (416)
#define FUNC_SIZE (64)
#define MISC_SIZE (32) /* for tracelevel_str + LINE */
#define DFT_FUNC_SIZE (23)

static const char * const tracelevel_str[] = {
	NULL, "ERR", "WAR", "INF", "DBG", "LOG", "FS "
};

static char strbuff[CONFIG_NR_CPUS][TRACE_SIZE + FUNC_SIZE + MISC_SIZE] = {0};
static char func_str[CONFIG_NR_CPUS][FUNC_SIZE] = {0};

void trace_kern(
	const char *func, int line, int level,
	const char *fmt, ...)
{
	va_list ap;
	int flen = 0, l = 0, cpu = 0;
	char *raw = NULL;
	char *dstraw = NULL;
	unsigned long flags = 0;

	if (!fmt || !func)
		return;

	local_irq_save(flags);

	cpu = percpu_id();
	raw = &strbuff[cpu][FUNC_SIZE + MISC_SIZE];

	flen = strnlen(func, FUNC_SIZE - 1);

	va_start(ap, fmt);
	l = vsnprintf(raw, TRACE_SIZE, fmt, ap);
	va_end(ap);

	memcpy(func_str[cpu], func, flen);
	if (flen <= DFT_FUNC_SIZE) {
		memset(&func_str[cpu][flen], ' ', (DFT_FUNC_SIZE - flen));
		func_str[cpu][DFT_FUNC_SIZE] = 0;
	} else {
		func_str[cpu][flen] = 0;
	}

	__atomic_store_n(&dstraw, raw, __ATOMIC_RELAXED);

	l = snprintf(strbuff[cpu], sizeof(strbuff[cpu]),
		 "[%s-%04u|%04u@CPU%02u]%s(%04d): %s", tracelevel_str[level],
		 current->id, current->proc->id, cpu, func_str[cpu], line, dstraw);

	if ((size_t)l < sizeof(strbuff[cpu]))
		printk_raw(strbuff[cpu], l);

	local_irq_restore(flags);
}
