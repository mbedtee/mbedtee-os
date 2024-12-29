// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * msleep() and usleep()
 */

#include <tevent.h>
#include <trace.h>
#include <sched.h>
#include <thread.h>

#include <sleep.h>

/*
 * This function sleeps for given number of milliseconds
 *
 * return the remain msecs.
 */
long msleep(unsigned long msecs)
{
	return sched_msecs(msecs);
}

/*
 * This function sleeps for given number of microseconds
 *
 * return the remain usecs.
 */
int usleep(useconds_t usecs)
{
	return sched_usecs(usecs);
}
