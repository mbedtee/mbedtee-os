// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * User Log Trace
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <defs.h>
#include <sched.h>
#include <utrace.h>
#include <pthread.h>
#include <pthread_mutexdep.h>

#define TRACE_SIZE (416)
#define FUNC_SIZE (64)
#define MISC_SIZE (32) /* for tracelevel_str + LINE */
#define DFT_FUNC_SIZE (23)

static const char * const tracelevel_str[] = {
	NULL, "ERR", "WAR", "INF", "DBG", "LOG"
};

static char strbuff[TRACE_SIZE + FUNC_SIZE + MISC_SIZE] = {0};

DECLARE_RECURSIVE_PTHREAD_MUTEX(_trace_lock);

void utrace(const char *func, int line,
	int level, const char *fmt, ...)
{
	va_list ap;
	char func_str[FUNC_SIZE];
	char *raw = &strbuff[FUNC_SIZE + MISC_SIZE];
	char *dstraw = NULL;
	int flen = 0, l = 0;

	flen = strnlen(func, FUNC_SIZE - 1);

	__pthread_mutex_lock(&_trace_lock);

	va_start(ap, fmt);
	vsnprintf(raw, TRACE_SIZE, fmt, ap);
	va_end(ap);

	memcpy(func_str, func, flen);
	if (flen <= DFT_FUNC_SIZE) {
		memset(func_str + flen, ' ', (DFT_FUNC_SIZE - flen));
		func_str[DFT_FUNC_SIZE] = 0;
	} else {
		func_str[flen] = 0;
	}

	__atomic_store_n(&dstraw, raw, __ATOMIC_RELAXED);

	l = snprintf(strbuff, sizeof(strbuff),
		"[%s %04u|%04u@CPU%02u]%s(%04d): %s", tracelevel_str[level],
		gettid(), getpid(), sched_getcpu(), func_str, line, dstraw);

	if ((size_t)l < sizeof(strbuff))
		write(STDOUT_FILENO, strbuff, l);

	__pthread_mutex_unlock(&_trace_lock);
}
