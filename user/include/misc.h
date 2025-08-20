/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * misc internal definitions for both user/kernel space
 */

#ifndef __MISCPRIV_H
#define __MISCPRIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <reent.h>
#include <sched.h>
#include <signal.h>

/* thread-width --> pthread_exit() */
#define SIGCANCEL 29
/* must be same SIGCANCEL, for alarm */
#define SIGTIMER SIGCANCEL

struct sigarguments {
	void *ctx;
	siginfo_t info;
};

#ifdef __cplusplus
}
#endif

#endif
