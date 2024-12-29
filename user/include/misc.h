/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * misc internal definitions for both user/kernel space
 */

#ifndef __MISCPRIV_H
#define __MISCPRIV_H

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
	int signo;
	siginfo_t info;
	void *ctx;
};

#endif
