/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * the kernel level definitions for userspace POSIX thread
 */

#ifndef _SYSPTHREAD_H
#define _SYSPTHREAD_H

#include <thread.h>

#include <pthread.h>

typedef thread_func_t pthread_func_t;

/*
 * Create the pthread which will run in userspace
 */
int pthread_kcreate(struct process *proc,
	pthread_attr_t *attr, pthread_func_t fn, void *data);

#endif
