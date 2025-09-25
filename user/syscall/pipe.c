// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 */

#include <syscall.h>

/*
 * newlib libc does not provide pipe()
 */
int pipe(int pipefd[2])
{
	long ret = syscall2(SYSCALL_PIPE, pipefd, 0);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

/*
 * pipe2: create pipe with flags (O_NONBLOCK/O_CLOEXEC)
 */
int pipe2(int pipefd[2], int flags)
{
	long ret = syscall2(SYSCALL_PIPE, pipefd, flags);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
