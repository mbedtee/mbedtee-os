// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel date/time utility
 */

#include <time.h>
#include <errno.h>
#include <sched.h>
#include <ktime.h>
#include <thread.h>

#include <thread_info.h>

static struct timespec systs = {0};

int clock_gettime(clockid_t clockid,
	struct timespec *ts)
{
	int ret = -EINVAL;

	ts->tv_sec = ts->tv_nsec = 0;

	switch (clockid) {
	case CLOCK_REALTIME:
		get_systime(&ts->tv_sec, &ts->tv_nsec);
		ret = 0;
		break;
	case CLOCK_MONOTONIC:
		read_time(ts);
		ret = 0;
		break;
#ifdef CONFIG_USER
	case CLOCK_THREAD_CPUTIME_ID:
		ret = sched_thread_cputime(current_id, ts);
		break;
	case CLOCK_PROCESS_CPUTIME_ID:
		ret = sched_process_cputime(current_id, ts);
		break;
#endif
	default:
		EMSG("invalid clockid %ld\n", clockid);
		break;
	}

	return ret;
}

void set_systime(time_t sec, long nsec)
{
	struct timespec mono = {0};
	struct timespec tv = {sec, nsec};

	read_time(&mono);

	timespecsub(&tv, &mono, &systs);
}

void get_systime(time_t *sec, long *nsec)
{
	struct timespec tv = {0};

	read_time(&tv);

	timespecadd(&tv, &systs, &tv);

	*sec = tv.tv_sec;

	if (nsec)
		*nsec = tv.tv_nsec;
}

#define LEAPS_THRU_END_OF(y) ((y)/4 - (y)/100 + (y)/400)

#define IS_LEAP_YEAR(x) ((!((x) % 4) && ((x) % 100)) || !((x) % 400))

static const unsigned char days_in_month[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static inline int lookup_days_in_month(int month, int year)
{
	return days_in_month[month] + (IS_LEAP_YEAR(year) && month == 1);
}

/*
 * time (seconds) to date
 * Convert seconds to date. (1970-01-01 00:00:00)
 */
void time2date(time_t time, struct tm *tm)
{
	unsigned int month, year, secs;
	int days;

	days = time / 86400;
	secs = time - (days * 86400);

	/* day of the week, 1970-01-01 was a Thursday */
	tm->tm_wday = (days + 4) % 7;

	year = 1970 + days / 365;
	days -= (year - 1970) * 365
		+ LEAPS_THRU_END_OF(year - 1)
		- LEAPS_THRU_END_OF(1970 - 1);
	while (days < 0) {
		year -= 1;
		days += 365 + IS_LEAP_YEAR(year);
	}
	tm->tm_year = year - 1900;
	tm->tm_yday = days + 1;

	for (month = 0; month < 11; month++) {
		int newdays;

		newdays = days - lookup_days_in_month(month, year);
		if (newdays < 0)
			break;
		days = newdays;
	}
	tm->tm_mon = month;
	tm->tm_mday = days + 1;

	tm->tm_hour = secs / 3600;
	secs -= tm->tm_hour * 3600;
	tm->tm_min = secs / 60;
	tm->tm_sec = secs - tm->tm_min * 60;

	tm->tm_isdst = 0;
}

/*
 * date to time (seconds)
 * Convert date to seconds since (1970-01-01 00:00:00)
 */
time_t date2time(int year, int mon, int day,
	int hour, int min, int second)
{
	time_t ydays = 0;
	time_t mdays = 0;
	time_t days = 0;

	mon -= 2;
	if (mon <= 0) {
		mon += 12;
		year -= 1;
	}

	if (year > 0)
		ydays = (year - 1) * 365 + year / 4 - year / 100 + year / 400;
	mdays = (367 * mon / 12) + 29;
	days = day - 1 + mdays + ydays - 719162;

	return (((days * 24 + hour) * 60 + min) * 60) + second;
}

/*
 * convert the abstime to microseconds for timed waits.
 */
int abstime2usecs(const struct timespec *abstime,	uint64_t *usecs)
{
	struct timespec now;
	struct timespec diff;

	if (INVALID_TIMESPEC(abstime))
		return -EINVAL;

	get_systime(&now.tv_sec, &now.tv_nsec);

	timespecsub(abstime, &now, &diff);

	if (diff.tv_sec < 0)
		return -ETIMEDOUT;

	*usecs = diff.tv_sec * 1000000UL + diff.tv_nsec / 1000UL;

	if (*usecs == 0)
		return -ETIMEDOUT;

	return 0;
}
