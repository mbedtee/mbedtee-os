// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * eventpoll
 */

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <syscall.h>

#include <epoll.h>

int epoll_create(int size)
{
	int ret = 0;

	ret = syscall1(SYSCALL_EPOLL_CREATE, size);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
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
