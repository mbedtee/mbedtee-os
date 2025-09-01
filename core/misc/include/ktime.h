/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * kernel data/time utility
 */

#ifndef _KTIME_H
#define _KTIME_H

#ifdef __cplusplus
extern "C" {
#endif

#include <timer.h>

/*
 * time (seconds) to date
 * Convert seconds to date. (1970-01-01 00:00:00)
 */
void time2date(time_t secs, struct tm *tm);

/*
 * date to time (seconds)
 * Convert date to seconds since (1970-01-01 00:00:00)
 */
time_t date2time(int year, int mon, int day,
	int hour, int min, int second);

/*
 * Set Seconds and Nano-seconds since (1970-01-01 00:00:00)
 */
void set_systime(time_t sec, long nsec);

/*
 * Get Seconds and Nano-seconds since (1970-01-01 00:00:00)
 *
 * nsec can be NULL
 */
void get_systime(time_t *sec, long *nsec);

/*
 * Parse timezone offset string "+HHMM" or "+HH:MM" to seconds.
 * e.g. "+0800" -> 28800, "-0530" -> -19800
 */
int tz_offset_secs(const char *tz);

/*
 * Set/Get the system timezone.
 * minuteswest: minutes west of UTC (e.g. UTC+8 => -480).
 */
void set_systz(int minuteswest);
void get_systz(int *minuteswest, int *dsttime);

/*
 * convert the abstime to microseconds for timed waits.
 */
int abstime2usecs
(
	const struct timespec *abstime,	uint64_t *usecs
);

#ifdef __cplusplus
}
#endif
#endif
