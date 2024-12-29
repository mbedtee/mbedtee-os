// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread cancellation functionalities
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <__pthread.h>

#include "pthread_auxiliary.h"

#define CANCEL_INVALID_STATE(state) \
	(((state) != PTHREAD_CANCEL_ENABLE) && \
	((state) != PTHREAD_CANCEL_DISABLE))

#define CANCEL_INVALID_TYPE(type) \
	(((type) != PTHREAD_CANCEL_DEFERRED) && \
	((type) != PTHREAD_CANCEL_ASYNCHRONOUS))

int	pthread_cancel(pthread_t pthread)
{
	int ret = 0;
	struct __pthread *t = NULL;

	t = __pthread_get(pthread);
	if (t == NULL) {
		ret = ESRCH;
		goto out;
	}

	if (t->cancel_pending) {
		ret = EEXIST;
		goto out;
	}

	t->cancel_pending = true;

	if (t->cancel_state != PTHREAD_CANCEL_ENABLE) {
		ret = EPERM;
		goto out;
	}

	if (t->cancel_type == PTHREAD_CANCEL_ASYNCHRONOUS) {
		t->cancel_state = PTHREAD_CANCEL_DISABLE;
		if (t == __pthread_self) {
			__pthread_exit(PTHREAD_CANCELED);
			__pthread_put(t);
		} else {
			do {
				ret = pthread_kill(pthread, SIGCANCEL);
			} while (ret == EAGAIN);
		}
	}

out:
	__pthread_put(t);
	return ret;
}

static void __pthread_testcancel(struct __pthread *t)
{
	int cancel_pending = false;

	cancel_pending = (t->cancel_state == PTHREAD_CANCEL_ENABLE)
					&& t->cancel_pending;

	if (cancel_pending) {
		t->cancel_state = PTHREAD_CANCEL_DISABLE;
		__pthread_exit(PTHREAD_CANCELED);
	}
}

int pthread_setcancelstate(int state, int *old_state)
{
	struct __pthread *t = __pthread_self;
	struct __pthread_aux *aux = aux_of(t);

	if (CANCEL_INVALID_STATE(state))
		return EINVAL;

	__pthread_mutex_lock(&aux->cancel_lock);
	if (old_state)
		*old_state = t->cancel_state;
	t->cancel_state = state;
	__pthread_testcancel(t);
	__pthread_mutex_unlock(&aux->cancel_lock);

	return 0;
}

int pthread_setcanceltype(int type, int *old_type)
{
	struct __pthread *t = __pthread_self;
	struct __pthread_aux *aux = aux_of(t);

	if (CANCEL_INVALID_TYPE(type))
		return EINVAL;

	__pthread_mutex_lock(&aux->cancel_lock);
	if (old_type)
		*old_type = t->cancel_type;
	t->cancel_type = type;
	__pthread_testcancel(t);
	__pthread_mutex_unlock(&aux->cancel_lock);

	return 0;
}

void __pthread_testcancelself(void)
{
	__pthread_testcancel(__pthread_self);
}

void pthread_testcancel(void)
{
	struct __pthread *t = __pthread_self;
	struct __pthread_aux *aux = aux_of(t);

	__pthread_mutex_lock(&aux->cancel_lock);
	__pthread_testcancel(t);
	__pthread_mutex_unlock(&aux->cancel_lock);
}
