/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * msleep() and usleep()
 */

#ifndef _SLEEP_H
#define _SLEEP_H

#include <sys/types.h>

/*
 * This function sleeps for given number of milliseconds
 *
 * return the remain msecs.
 */
long msleep(unsigned long msecs);

/*
 * This function sleeps for given number of microseconds
 * and schedules the next thread
 */
int usleep(useconds_t usecs);

#endif
