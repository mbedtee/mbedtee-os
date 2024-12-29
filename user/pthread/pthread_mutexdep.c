// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread mutex dependences
 */

#include <sched.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include "pthread_auxiliary.h"
#include "pthread_waitdep.h"
#include "pthread_lockdep.h"
#include "pthread_mutexdep.h"
#include "pthread_wait.h"
#include "pthread_time.h"

static const DECLARE_DEFAULT_PTHREAD_MUTEX_ATTR(local_mattr);

int	__pthread_mutex_init(__pthread_mutex_t *m,
	const pthread_mutexattr_t *attr)
{
	if (!m)
		return EINVAL;

	if (attr) {
		if (!attr->is_initialized)
			return EINVAL;
		if (MUTEX_INVALID_PSHARE(attr->process_shared))
			return EINVAL;
		if (MUTEX_INVALID_PRIOCEILING(attr->prio_ceiling))
			return EINVAL;
		if (MUTEX_INVALID_PROTOCOL(attr->protocol))
			return EINVAL;
		if (MUTEX_INVALID_TYPE(attr->type))
			return EINVAL;
	}

	memcpy(&m->attr, attr ? attr : &local_mattr,
		sizeof(pthread_mutexattr_t));

	if (!attr)
		m->attr.prio_ceiling = sched_get_priority_max(SCHED_RR);

	m->rc = 0;
	m->owner = 0;
	m->state = MUTEX_STATE_NORMAL;
	m->lock = 0;

	return 0;
}

int	__pthread_mutex_destroy(__pthread_mutex_t *m)
{
	return 0;
}

int	__pthread_mutex_trylock(__pthread_mutex_t *m)
{
	uint32_t val = 0;
	struct __pthread *self = __pthread_self;
	int protocol = -1;
	int prio_ceiling = -1;
	int type = -1;
	int ret = 0;

	if (!m)
		return EINVAL;

	protocol = m->attr.protocol;
	type = m->attr.type;
	prio_ceiling = m->attr.prio_ceiling;

	if ((protocol == PTHREAD_PRIO_PROTECT) &&
		(DEFAULT_PRIORITY(self) > prio_ceiling))
		return EINVAL;

	pthread_enter_critical(self);

	if (__atomic_compare_exchange_n(&m->lock, &val,
		PTHREAD_LOCK_WRLOCK, 1, __ATOMIC_SEQ_CST,
		__ATOMIC_RELAXED))
		goto locked;

	if (m->owner == self->pthread) {
		if (type == PTHREAD_MUTEX_RECURSIVE) {
			m->rc++;
			goto out;
		}

		if (type == PTHREAD_MUTEX_ERRORCHECK) {
			ret = EDEADLK;
			goto out;
		}
	}

	ret = EBUSY;
	goto out;

locked:
	m->rc++;
	m->owner = self->pthread;
	m->state = MUTEX_STATE_NORMAL;
	list_add_tail(&m->node, &aux_of(self)->mutexs);
	if ((protocol == PTHREAD_PRIO_PROTECT) &&
		(self->priority != prio_ceiling)) {
		if (!self->priority_bak)
			self->priority_bak = self->priority;
		pthread_setschedprio(self->pthread, prio_ceiling);
	}

	return 0;

out:
	pthread_leave_critical(self);
	return ret;
}

int __pthread_mutex_lock(__pthread_mutex_t *m)
{
	uint32_t val = 0;
	struct __pthread *self = __pthread_self;
	int protocol = -1;
	int prio_ceiling = -1;
	int type = -1;
	int ret = 0;

	if (!m)
		return EINVAL;

	protocol = m->attr.protocol;
	type = m->attr.type;
	prio_ceiling = m->attr.prio_ceiling;

	if ((protocol == PTHREAD_PRIO_PROTECT) &&
		(DEFAULT_PRIORITY(self) > prio_ceiling))
		return EINVAL;

	pthread_enter_critical(self);

	while (val == 0) {
		if (__atomic_compare_exchange_n(&m->lock, &val,
			PTHREAD_LOCK_WRLOCK, 0, __ATOMIC_ACQUIRE,
			__ATOMIC_RELAXED))
			goto locked;

		/*
		 * val isn't 0, increase the nr of waiter, goto wait.
		 * runs here, means the lock is possibly held by other
		 * writer or readers, but condition maybe change at this
		 * critical moment, just make sure of this
		 */
		val = __atomic_load_n(&m->lock, __ATOMIC_RELAXED);
		if (val) {
			if (m->owner == self->pthread) {
				if (type == PTHREAD_MUTEX_RECURSIVE) {
					m->rc++;
					goto out;
				}

				if (type == PTHREAD_MUTEX_ERRORCHECK) {
					ret = EDEADLK;
					goto out;
				}
			}

			/*
			 * PTHREAD_PRIO_INHERIT try to give a more higher
			 * priority to let the original owner run ASAP
			 */
			ret = __pthread_wait_wrlock(&m->lock,
					(protocol == PTHREAD_PRIO_INHERIT) ?
						tid_of(m->owner) : 0);
			if (ret != 0)
				goto out;
			goto locked;
		}
	}

locked:
	m->rc++;
	m->owner = self->pthread;
	m->state = MUTEX_STATE_NORMAL;
	list_add_tail(&m->node, &aux_of(self)->mutexs);
	if ((protocol == PTHREAD_PRIO_PROTECT) &&
		(self->priority != prio_ceiling)) {
		if (!self->priority_bak)
			self->priority_bak = self->priority;
		pthread_setschedprio(self->pthread, prio_ceiling);
	}
	return 0;

out:
	pthread_leave_critical(self);
	return ret;
}

int	__pthread_mutex_timedlock(__pthread_mutex_t *m,
	const struct timespec *abstime)
{
	uint32_t val = 0;
	struct __pthread *self = __pthread_self;
	int protocol = -1;
	int prio_ceiling = -1;
	int type = -1;
	int ret = 0;
	long usecs = 0;

	if (!m)
		return EINVAL;

	protocol = m->attr.protocol;
	type = m->attr.type;
	prio_ceiling = m->attr.prio_ceiling;

	if ((protocol == PTHREAD_PRIO_PROTECT) &&
		(DEFAULT_PRIORITY(self) > prio_ceiling))
		return EINVAL;

	pthread_enter_critical(self);

	while (val == 0) {
		if (__atomic_compare_exchange_n(&m->lock, &val,
			PTHREAD_LOCK_WRLOCK, 0, __ATOMIC_ACQUIRE,
			__ATOMIC_RELAXED))
			goto locked;

		/*
		 * val isn't NULL, increase the nr of waiter, goto wait.
		 * runs here, means the lock is possibly held by other
		 * writer or readers, but condition maybe change at this
		 * critical moment, just make sure of it
		 */
		val = __atomic_load_n(&m->lock, __ATOMIC_RELAXED);
		if (val) {
			if (m->owner == self->pthread) {
				if (type == PTHREAD_MUTEX_RECURSIVE) {
					m->rc++;
					goto out;
				}

				if (type == PTHREAD_MUTEX_ERRORCHECK) {
					ret = EDEADLK;
					goto out;
				}
			}

			ret = __pthread_time2usecs(abstime, &usecs);
			if (ret != 0)
				goto out;

			/*
			 * PTHREAD_PRIO_INHERIT try to give a more higher
			 * priority to let the original owner run ASAP
			 */
			ret = __pthread_timedwait_wrlock(&m->lock,
						(protocol == PTHREAD_PRIO_INHERIT) ?
							tid_of(m->owner) : 0, usecs);
			if (ret != 0)
				goto out;

			goto locked;
		}
	}

locked:
	m->rc++;
	m->owner = self->pthread;
	m->state = MUTEX_STATE_NORMAL;
	list_add_tail(&m->node, &aux_of(self)->mutexs);
	if ((protocol == PTHREAD_PRIO_PROTECT) &&
		(self->priority != prio_ceiling)) {
		if (!self->priority_bak)
			self->priority_bak = self->priority;
		pthread_setschedprio(self->pthread, prio_ceiling);
	}

	return 0;

out:
	pthread_leave_critical(self);
	return ret;
}

int	__pthread_mutex_unlock(__pthread_mutex_t *m)
{
	uint32_t val = 0;
	struct __pthread *self = __pthread_self;

	if (!m || (m->rc == 0))
		return EINVAL;

	if (m->owner != self->pthread)
		return EPERM;

	val = __atomic_load_n(&m->lock, __ATOMIC_RELAXED);
	if ((val & PTHREAD_LOCK_WRLOCK) != PTHREAD_LOCK_WRLOCK)
		return EINVAL;

	if (--m->rc == 0) {
		m->owner = 0;
		list_del(&m->node);
		val = __atomic_exchange_n(&m->lock, 0, __ATOMIC_RELEASE);
		__pthread_wakeup_lock(&m->lock, val & PTHREAD_LOCK_WAITER);

		if (self->priority_bak) {
			if (!self->exiting)
				pthread_setschedprio(self->pthread, self->priority_bak);
			self->priority_bak = 0;
		}

		pthread_leave_critical(self);
	}

	return 0;
}
