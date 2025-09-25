// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * eventfd() userspace syscall wrapper
 */

#include <eventfd.h>
#include <syscall.h>

int eventfd(unsigned int initval, int flags)
{
	long ret = syscall2(SYSCALL_EVENTFD2, initval, flags);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int eventfd_read(int fd, eventfd_t *value)
{
	ssize_t rc = 0;

	if (!value) {
		errno = EINVAL;
		return -1;
	}

	rc = read(fd, value, sizeof(*value));
	if (rc < 0)
		return -1;
	if (rc != sizeof(*value)) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int eventfd_write(int fd, eventfd_t value)
{
	ssize_t rc = 0;

	rc = write(fd, &value, sizeof(value));
	if (rc < 0)
		return -1;
	if (rc != sizeof(value)) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}
