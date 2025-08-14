/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * pthread independent (thread-specific data visible to all threads
 * in the process)
 */

#ifndef _PTHREAD_KEY_H
#define _PTHREAD_KEY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <list.h>

#include "pthread_auxiliary.h"

void __pthread_key_destructor(struct __pthread *t);

#ifdef __cplusplus
}
#endif

#endif
