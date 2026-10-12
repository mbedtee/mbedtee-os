// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * eventpoll
 */

#include <fcntl.h>

#include <syscall.h>

#include <epoll.h>

int epoll_create(int size)
{
	int ret = 0;

	ret = syscall1(SYSCALL_EPOLL_CREATE, size);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int epoll_create1(int flags)
{
	int ret = 0, fd = 0;

	if (flags & ~EPOLL_CLOEXEC) {
		errno = EINVAL;
		return -1;
	}

	fd = epoll_create(1);
	if (fd < 0)
		return fd;

	if (flags & EPOLL_CLOEXEC) {
		ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			int err = errno;

			close(fd);
			errno = err;
			return -1;
		}
	}

	return fd;
}

int epoll_ctl(int epfd, int op, int fd,
		      struct epoll_event *event)
{
	int ret = 0;

	ret = syscall4(SYSCALL_EPOLL_CTL, epfd, op, fd, event);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int epoll_wait(int epfd, struct epoll_event *events,
		       int maxevents, int timemsecs)
{
	int ret = 0;

	ret = syscall4(SYSCALL_EPOLL_WAIT, epfd, events, maxevents, timemsecs);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
