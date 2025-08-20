// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * __assert_func stub for user space Newlib assert()
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>

#include <pthread.h>
#include <backtrace.h>

__weak_symbol void __assert_func(const char *file,
	int line, const char *func, const char *expr)
{
	int len = 0;
	char tracestr[200];

	len = snprintf(tracestr, sizeof(tracestr),
			"\n!!oops-%04u|%04u@CPU%d %s() L%d expr: %s\n",
			gettid(), getpid(), sched_getcpu(),
			func ? func : "nil", line, expr);

	if (len > 0) {
		if (len >= sizeof(tracestr))
			len = sizeof(tracestr) - 1;
		write(STDERR_FILENO, tracestr, len);
	}
	backtrace();

	pthread_exit((void *)EFAULT);
}
