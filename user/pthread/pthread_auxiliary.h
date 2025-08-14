/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * pthread internal auxiliary struct/functionalities - userspace only
 */

#ifndef _PTHREAD_AUX_H
#define	_PTHREAD_AUX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <syscall.h>

#include "pthread_wait.h"
#include "pthread_reent.h"

struct __pthread_aux {
	/*
	 * node in the process's __pthreads list
	 */
	struct list_head node;

	/*
	 * mutexes held by this thread
	 */
	struct list_head mutexes;

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
	struct __pthread_mutex cancel_lock;

	/*
	 * reference counter for __pthread_get/__pthread_put
	 */
	int refc;

	/*
	 * waitqueue for joiners
	 */
	struct __pthread_waitqueue join_q;
};

#define PTHREAD_AUX_OFFSET (PTHREAD_REENT_OFFSET + sizeof(struct _reent))

#define pthread_aux(t) ((struct __pthread_aux *)((long)(t) + PTHREAD_AUX_OFFSET))
#define pthread_of(aux) ((struct __pthread *)((long)(aux) - PTHREAD_AUX_OFFSET))

void __pthread_init(struct __pthread *t);

void __dead2 __pthread_exit(void *retval);

struct __pthread *__pthread_get(pthread_t id);

void __pthread_put(struct __pthread *t);

void __pthread_join_wait(struct __pthread_aux *aux, void **value_ptr);

static inline long __pthread_create(
	pthread_t *dst,
	const pthread_attr_t *attr,
	void *(*routine)(void *),
	void *arg)
{
	int old_state = 0;
	struct __pthread *t = NULL;

	if (attr) {
		if (attr->stackaddr && attr->stacksize == 0)
			return EINVAL;
		if (!attr->stackaddr && attr->stacksize != 0)
			return EINVAL;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
	t = (void *)syscall3(SYSCALL_PTHREAD_CREATE, attr, routine, arg);
	pthread_setcancelstate(old_state, NULL);
	if (IS_ERR_PTR(t))
		return syscall_errno(PTR_ERR(t));

	__pthread_init(t);

	*dst = t->pthread;

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif
