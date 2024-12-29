// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * timer
 */

#include <errno.h>
#include <syscall.h>
#include <time.h>

int clock_getcpuclockid(pid_t pid, clockid_t *clockid)
{
	if ((pid != getpid()) && (pid != 0))
		return EPERM;

	*clockid = CLOCK_PROCESS_CPUTIME_ID;
	return 0;
}

int clock_gettime(clockid_t clockid, struct timespec *t)
{
	int ret = 0;

	ret = syscall3(SYSCALL_CLOCKGETTIME, clockid, t, NULL);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int timer_create(clockid_t clockid, struct sigevent *evp,
	timer_t *timerid)
{
	int ret = 0;

	ret = syscall3(SYSCALL_TIMER_CREATE, clockid, evp, timerid);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int timer_delete(timer_t timerid)
{
	int ret = 0;

	ret = syscall1(SYSCALL_TIMER_DELETE, timerid);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int timer_gettime(timer_t timerid, struct itimerspec *value)
{
	int ret = 0;

	ret = syscall2(SYSCALL_TIMER_GETTIME, timerid, value);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int timer_settime(timer_t timerid, int flags,
		const struct itimerspec *value,
		struct itimerspec *ovalue)
{
	int ret = 0;

	ret = syscall4(SYSCALL_TIMER_SETTIME, timerid, flags, value, ovalue);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int timer_getoverrun(timer_t timerid)
{
	int ret = 0;

	ret = syscall1(SYSCALL_TIMER_GETOVERRUN, timerid);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
