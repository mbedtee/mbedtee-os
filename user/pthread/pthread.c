// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * pthread functionalities
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <utrace.h>
#include <signal.h>
#include <syscall.h>

#include "pthread_auxiliary.h"
#include "pthread_cond.h"

int	pthread_create(pthread_t *pthread,
	const pthread_attr_t *attr,
	void *(*routine)(void *), void *arg)
{
	pthread_testcancel();

	return __pthread_create(pthread, attr, routine, arg);
}

int	pthread_join(pthread_t pthread, void **value_ptr)
{
	struct __pthread *t = NULL;
	struct __pthread *self = __pthread_self;
	struct __pthread_aux *aux = NULL;

	pthread_testcancel();

	t = __pthread_get(pthread);
	if (!t)
		return ESRCH;

	if (t->detachstate != PTHREAD_CREATE_JOINABLE) {
		__pthread_put(t);
		return EINVAL;
	}

	if (self == t) {
		__pthread_put(t);
		return EDEADLK;
	}

	t->detachstate = PTHREAD_CREATE_DETACHED;

	aux = pthread_aux(t);

	if (t->detaching) {
		pthread_sigqueue(pthread, SIGCANCEL,
				(union sigval)(aux->join_q.notification));
	}

	__pthread_join_wait(aux, value_ptr);

	return 0;
}

int	pthread_detach(pthread_t pthread)
{
	int ret = -1;
	struct __pthread *t = NULL;

	t = __pthread_get(pthread);
	if (!t) {
		ret = ESRCH;
		goto err;
	}

	if (t->detachstate != PTHREAD_CREATE_JOINABLE) {
		ret = EINVAL;
		goto err;
	}

	t->detachstate = PTHREAD_CREATE_DETACHED;

	if (t->detaching)
		pthread_kill(pthread, SIGCANCEL);

	ret = 0;

err:
	__pthread_put(t);
	return ret;
}

void pthread_exit(void *ret)
{
	__pthread_exit(ret);
}

pthread_t pthread_self(void)
{
	return __pthread_self->pthread;
}

int	pthread_equal(pthread_t t1, pthread_t t2)
{
	return t1 == t2;
}

int	pthread_getcpuclockid(pthread_t thread,
	clockid_t *clockid)
{
	struct __pthread *t = NULL;

	t = __pthread_get(thread);
	if (!t)
		return ESRCH;

	*clockid = CLOCK_THREAD_CPUTIME_ID;

	__pthread_put(t);
	return 0;
}

/*
 * If an implementation does not support multiplexing of
 * user threads on top of several kernel-scheduled entities,
 * the concurrency functions are provided for source code
 * compatibility but they shall have no effect when called.
 */
static int __pthread_concurrency_level;
int	pthread_setconcurrency(int new_level)
{
	if (new_level < 0)
		return EINVAL;

	__pthread_concurrency_level = new_level;

	return 0;
}
int	pthread_getconcurrency(void)
{
	return __pthread_concurrency_level;
}

int	pthread_once(pthread_once_t *once_control,
	void (*init_routine)(void))
{
	int *init_executed = &once_control->init_executed;
	int init_val = 0;

	/*
	 * POSIX requires: on return from pthread_once(),
	 * init_routine shall have completed.
	 *
	 * State transitions: 0 (UNINIT) -> 1 (RUNNING) -> 2 (DONE)
	 */
	if (__atomic_load_n(init_executed, __ATOMIC_ACQUIRE) == 2)
		return 0;

	if (__atomic_compare_exchange_n(init_executed, &init_val,
		1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		init_routine();
		__atomic_store_n(init_executed, 2, __ATOMIC_RELEASE);
	} else {
		while (__atomic_load_n(init_executed, __ATOMIC_ACQUIRE) != 2)
			pthread_yield();
	}

	return 0;
}
