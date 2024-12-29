/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread time conversion
 */

#ifndef _PTHREAD_TIME_H
#define	_PTHREAD_TIME_H

#include <sys/time.h>

/*
 * convert the time to microseconds for timed waits.
 */
static inline int __pthread_time2usecs
(
	const struct timespec *abstime,	long *usecs
)
{
	int ret = 0;
	struct timespec now = {0};
	struct timespec diff = {0};

	if ((abstime->tv_sec < 0) ||
		((unsigned long)abstime->tv_nsec >= 1000000000UL)) {
		ret = EINVAL;
		goto out;
	}

	clock_gettime(CLOCK_REALTIME, &now);

	timespecsub(abstime, &now, &diff);

	if (diff.tv_sec < 0) {
		ret = ETIMEDOUT;
		goto out;
	}

	*usecs = diff.tv_sec * 1000000UL + diff.tv_nsec/1000UL;

	if (*usecs == 0)
		ret = ETIMEDOUT;

out:
	return ret;
}

#endif
