/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * the kernel level definitions for userspace POSIX thread
 */

#ifndef _SYSPTHREAD_H
#define _SYSPTHREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <thread.h>

#include <pthread.h>

typedef thread_func_t pthread_func_t;

/*
 * Create the pthread which will run in userspace
 */
int pthread_kcreate(struct process *proc,
	pthread_attr_t *attr, pthread_func_t fn, void *data);

/*
 * Cleanup the just created thread (never run)
 */
void pthread_destroy(struct thread *t);

#ifdef __cplusplus
}
#endif
#endif
