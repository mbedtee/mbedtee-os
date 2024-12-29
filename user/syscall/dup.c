// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * dup() and dup2()
 */

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>

#include <syscall.h>

int dup(int oldfd)
{
	int ret = -1;

	ret = syscall1(SYSCALL_DUP, oldfd);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int dup2(int oldfd, int newfd)
{
	int ret = -1;

	ret = syscall2(SYSCALL_DUP2, oldfd, newfd);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
