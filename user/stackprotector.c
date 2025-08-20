// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * stubs for the gcc stack-protetor.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syscall.h>
#include <backtrace.h>

unsigned long __stack_chk_guard = 0;

void __stack_chk_fail(void)
{
	char msg[] = "\noops-stack smashing detected\n";

	write(STDERR_FILENO, msg, sizeof(msg) - 1);

	backtrace_exit();
}
