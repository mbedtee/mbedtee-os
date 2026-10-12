// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * msleep() and usleep()
 */

#include <tevent.h>
#include <trace.h>
#include <sched.h>
#include <thread.h>
#include <ksignal.h>

#include <sleep.h>

/*
 * Linux do_nanosleep(): only the timeout or a pending signal ends a sleep;
 * any other wakeup sleeps off the remainder.
 */
static bool sleep_aborted(int interruptible)
{
	if (interruptible)
		return is_sigpending(current);

	/* an uninterruptible sleeper still has to stay killable */
	return !!(sigppending(current) &
		(BIT(SIGKILL) | BIT(SIGCANCEL) | BIT(SIGSTOP)));
}

static long sleep_msecs(unsigned long msecs, int interruptible)
{
	uint64_t remain = msecs;

	while (remain != 0) {
		remain = sched_msecs(remain, interruptible);
		if ((remain == 0) || sleep_aborted(interruptible))
			break;
	}

	return remain;
}

static long sleep_usecs(useconds_t usecs, int interruptible)
{
	uint64_t remain = usecs;

	while (remain != 0) {
		remain = sched_usecs(remain, interruptible);
		if ((remain == 0) || sleep_aborted(interruptible))
			break;
	}

	return remain;
}

/*
 * This function sleeps for given number of milliseconds
 *
 * Returns the remaining milliseconds.
 */
long msleep(unsigned long msecs)
{
	return sleep_msecs(msecs, false);
}

/*
 * This function sleeps for given number of microseconds
 *
 * Returns the remaining microseconds.
 */
int usleep(useconds_t usecs)
{
	return sleep_usecs(usecs, false);
}

/*
 * This function sleeps for given number of milliseconds
 *
 * Returns the remaining milliseconds.
 */
long msleep_interruptible(unsigned long msecs)
{
	return sleep_msecs(msecs, true);
}

/*
 * This function sleeps for given number of microseconds
 *
 * Returns the remaining microseconds.
 */
long usleep_interruptible(useconds_t usecs)
{
	return sleep_usecs(usecs, true);
}

