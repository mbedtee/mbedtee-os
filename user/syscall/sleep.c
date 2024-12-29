// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * usleep() and sleep()
 */

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
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
	return syscall1(SYSCALL_MSLEEP, (unsigned long)seconds * 1000UL);
}
