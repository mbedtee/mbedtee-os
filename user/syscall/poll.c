// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * poll(), select(), pselect()
 */

#include <syscall.h>

#include <poll.h>
#include <sys/select.h>

/*
 * timemsecs:
 *    > 0 : wait timeout msecs
 *    = 0 : no blocking
 *    < 0 : infinite blocking
 */
int poll(struct pollfd *fds, nfds_t nfds, int timemsecs)
{
	int ret = 0;

	ret = syscall3(SYSCALL_POLL, fds, nfds, timemsecs);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
	   fd_set *exceptfds, struct timeval *timeout)
{
	int ret = 0;

	ret = syscall5(SYSCALL_SELECT, nfds, readfds, writefds,
		       exceptfds, timeout);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds,
	    fd_set *exceptfds, const struct timespec *timeout,
	    const sigset_t *sigmask)
{
	int ret = 0;

	ret = syscall6(SYSCALL_PSELECT, nfds, readfds, writefds,
		       exceptfds, timeout, sigmask);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
