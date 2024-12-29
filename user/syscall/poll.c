// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * poll()
 */

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <syscall.h>

#include <poll.h>

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
