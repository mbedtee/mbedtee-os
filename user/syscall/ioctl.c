// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ioctl() function
 */

#include <errno.h>
#include <stdarg.h>
#include <ioctl.h>

#include <syscall.h>

int ioctl(int fd, int request, ...)
{
	int ret = 0;
	void *arg = NULL;
	va_list args = {0};

	if (syscall_stdfd(fd))
		return 0;

	va_start(args, NULL);
	arg = va_arg(args, void *);
	ret = syscall3(SYSCALL_IOCTL, fd, request, arg);
	va_end(args);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
