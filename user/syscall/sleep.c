// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * usleep() and sleep()
 */

#include <pthread.h>
#include <syscall.h>

int usleep(useconds_t us)
{
	long ret = 0;

	pthread_testcancel();

	ret = syscall1(SYSCALL_USLEEP, us);

	/* a positive value is the unslept time: report EINTR per POSIX */
	if (ret > 0) {
		errno = EINTR;
		return -1;
	}

	return ret;
}

unsigned int sleep(unsigned int seconds)
{
	long ret = 0;

	pthread_testcancel();

	ret = syscall1(SYSCALL_MSLEEP, seconds * 1000UL);

	/* msleep_interruptible() reports unslept ms; sleep() reports seconds */
	if (ret > 0)
		return (unsigned int)((ret + 999) / 1000);

	return 0;
}
