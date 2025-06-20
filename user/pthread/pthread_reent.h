/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * reentrant struct for each pthread
 */

#ifndef _PTHREAD_REENT_H
#define _PTHREAD_REENT_H

#include <__pthread.h>

#define PTHREAD_REENT_OFFSET sizeof(struct __pthread)

#define reent_of(t) ((struct _reent *)((long)t + PTHREAD_REENT_OFFSET))

#endif
