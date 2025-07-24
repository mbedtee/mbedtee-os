// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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
 * Returns the remaining milliseconds.
 */
long msleep(unsigned long msecs)
{
	return sched_msecs(msecs, false);
}

/*
 * This function sleeps for given number of microseconds
 *
 * Returns the remaining microseconds.
 */
int usleep(useconds_t usecs)
{
	return sched_usecs(usecs, false);
}

/*
 * This function sleeps for given number of milliseconds
 *
 * Returns the remaining milliseconds.
 */
long msleep_interruptible(unsigned long msecs)
{
	return sched_msecs(msecs, true);
}

/*
 * This function sleeps for given number of microseconds
 *
 * Returns the remaining microseconds.
 */
int usleep_interruptible(useconds_t usecs)
{
	return sched_usecs(usecs, true);
}

