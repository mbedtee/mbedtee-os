// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * usleep() and sleep()
 */

#include <pthread.h>
#include <syscall.h>

int usleep(useconds_t us)
{
	pthread_testcancel();
	return syscall1(SYSCALL_USLEEP, us);
}

unsigned int sleep(unsigned int seconds)
{
	pthread_testcancel();
	return syscall1(SYSCALL_MSLEEP, seconds * 1000UL);
}
