// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * Minimal waitpid() syscall wrapper.
 */

#include <errno.h>
#include <syscall.h>
#include <waitpid.h>

pid_t waitpid(pid_t pid, int *status, int options)
{
	long ret = -EINVAL;

	if (pid != 0 && pid >= -1)
		ret = syscall3(SYSCALL_WAITPID, pid, status, options);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
