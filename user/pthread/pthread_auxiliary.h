/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread internal auxiliary struct/functionalities - userspace only
 */

#ifndef _PTHREAD_AUX_H
#define	_PTHREAD_AUX_H

#include <syscall.h>

#include "pthread_reent.h"
#include "pthread_wait.h"

struct __pthread_aux {
	/*
	 * node in the process's __pthreads list
	 */
	struct list_head node;

	/*
	 * mutexs held by this thread
	 */
	struct list_head mutexs;

	/*
	 * keys of this thread
	 */
	struct list_head keys;

	/* wait points of this thread */
	struct list_head wqnodes;

	/*
	 * cleanup handlers for this thread
	 */
	struct __pthread_cleanup *cleanups;

	/*
	 * state lock for cancel/join/exit
	 */
	__pthread_mutex_t cancel_lock;

	/*
	 * waitqueue for joiners
	 */
	struct __pthread_waitqueue join_q;
};

#define PTHREAD_AUX_OFFSET (PTHREAD_REENT_OFFSET + sizeof(struct _reent))

#define aux_of(t) ((struct __pthread_aux *)((long)t + PTHREAD_AUX_OFFSET))

void __dead2 __pthread_exit(void *retval);

struct __pthread *__pthread_get(pthread_t id);

void __pthread_put(struct __pthread *t);

static inline long __pthread_create(
	pthread_t *dst,
	const pthread_attr_t *attr,
	void *(*routine)(void *),
	void *arg)
{
	long ret = -1;
	int old_state = 0;

	if (attr) {
		if (attr->stackaddr && !attr->stacksize)
			return -EINVAL;
		if (!attr->stackaddr && attr->stacksize)
			return -EINVAL;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
	ret = syscall3(SYSCALL_PTHREAD_CREATE, attr, routine, arg);
	pthread_setcancelstate(old_state, NULL);
	if (syscall_errno(ret))
		return syscall_errno(ret);

	*dst = (pthread_t)ret;

	return 0;
}

#endif
