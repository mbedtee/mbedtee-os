/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * msleep() and usleep()
 */

#ifndef _SLEEP_H
#define _SLEEP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * This function sleeps for given number of milliseconds
 *
 * Returns the number of remaining milliseconds.
 */
long msleep(unsigned long msecs);

/*
 * This function sleeps for given number of microseconds
 * and schedules the next thread.
 */
int usleep(useconds_t usecs);

/*
 * This function sleeps for given number of milliseconds
 *
 * Returns the number of remaining milliseconds.
 */
long msleep_interruptible(unsigned long msecs);

/*
 * This function sleeps for given number of microseconds
 *
 * Returns the number of remaining microseconds.
 */
int usleep_interruptible(useconds_t usecs);

#ifdef __cplusplus
}
#endif
#endif
