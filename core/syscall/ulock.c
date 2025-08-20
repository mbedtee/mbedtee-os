// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * syscall for user-mutex wait/wakeup
 */

#include <errno.h>
#include <trace.h>
#include <atomic.h>
#include <strings.h>
#include <wait.h>
#include <kmalloc.h>
#include <uaccess.h>
#include <thread.h>
#include <thread_info.h>
#include <__pthread.h>

#include "ulock.h"

static int __writer_locked(struct thread *curr,
	uint32_t *ulock, pid_t *owner)
{
	int val = 0, wrval = 0;
	struct atomic_num *l = (struct atomic_num *)ulock;

	do {
		if (atomic_compare_set(l, &val, PTHREAD_LOCK_WRLOCK))
			return true;

		/*
		 * val isn't 0, so increase the number of waiters and go
	 	 * to sleep.
		 * Reaching here means the lock may be held by another
		 * writer or by readers, but the condition may change at
		 * this critical moment, so make sure of it.
		 */
		while (val != 0) {
			if (*owner) {
				sched_inherit_prio(curr->sched, *owner);
				*owner = 0;
			}

			if (val & PTHREAD_LOCK_WAITER)
				return false;

			wrval = val | PTHREAD_LOCK_WAITER;
			if (atomic_compare_set(l, &val, wrval))
				return false;
		}
	} while (val == 0);

	return false;
}

static int __reader_locked(uint32_t *ulock)
{
	int val = 0, rdval = 0;
	struct atomic_num *l = (struct atomic_num *)ulock;

	while ((val & PTHREAD_LOCK_WRLOCK) == 0) {
		rdval = (val + PTHREAD_LOCK_READER) | PTHREAD_LOCK_RDLOCK;
		if (atomic_compare_set(l, &val, rdval))
			return true;

		/*
		 * Reaching here means the lock may be held by a writer,
		 * so increase the number of waiters and prepare to wait.
		 * The condition may change at this critical moment, so
		 * make sure of it.
		 */
		while (val & PTHREAD_LOCK_WRLOCK) {
			if (val & PTHREAD_LOCK_WAITER)
				return false;

			rdval = val | PTHREAD_LOCK_WAITER;
			if (atomic_compare_set(l, &val, rdval))
				return false;
		}
	}

	return false;
}

static int __wait_writer_lock(struct thread *t,
	uint32_t *l, pid_t *owner, uint64_t usecs)
{
	int ret = 0;
	long remain = 0;
	struct waitqueue *wq = &t->proc->wq;

	__pthread_leave_critical(t->tuser);

	/*
	 * if timeout == 0, then wait infinitely
	 */
	if (usecs == 0) {
		ret = wait_event_priv_interruptible(wq, __writer_locked(t, l, owner), l);
		ret = (ret != -EINTR) ? 0 : ret;
	} else {
		remain = wait_event_timeout_priv_interruptible(wq,
				__writer_locked(t, l, owner), usecs, l);
		ret = (remain > 0) ? 0 : (remain == 0) ? -ETIMEDOUT : remain;
	}

	__pthread_enter_critical(t->tuser);

	return ret;
}

static int __wait_reader_lock(struct thread *t,
	uint32_t *l, uint64_t usecs)
{
	int ret = 0;
	long remain = 0;
	struct waitqueue *wq = &t->proc->wq;

	__pthread_leave_critical(t->tuser);

	/*
	 * if timeout == 0, then wait infinitely
	 */
	if (usecs == 0) {
		ret = wait_event_priv_interruptible(wq, __reader_locked(l), l);
		ret = (ret != -EINTR) ? 0 : ret;
	} else {
		remain = wait_event_timeout_priv_interruptible(wq,
				__reader_locked(l), usecs, l);
		ret = (remain > 0) ? 0 : (remain == 0) ? -ETIMEDOUT : remain;
	}

	__pthread_enter_critical(t->tuser);

	return ret;
}

/*
 * reader waiting
 */
long do_syscall_wait_rdlock(struct thread_ctx *regs)
{
	uint32_t *ulock = (void *)regs->r[ARG_REG + 1];
	long timeout = regs->r[ARG_REG + 2];

	local_irq_disable();

	if ((long)ulock & (sizeof(uint32_t) - 1))
		return -EFAULT;

	if (!access_ok(ulock, sizeof(uint32_t)))
		return -EFAULT;

	return __wait_reader_lock(current, ulock, timeout);
}

/*
 * writer waiting
 */
long do_syscall_wait_wrlock(struct thread_ctx *regs)
{
	uint32_t *ulock = (void *)regs->r[ARG_REG + 1];
	pid_t owner = regs->r[ARG_REG + 2];
	long timeout = regs->r[ARG_REG + 3];

	local_irq_disable();

	if ((long)ulock & (sizeof(uint32_t) - 1))
		return -EFAULT;

	if (!access_ok(ulock, sizeof(uint32_t)))
		return -EFAULT;

	return __wait_writer_lock(current, ulock, &owner, timeout);
}

long do_syscall_wake_lock(struct thread_ctx *regs)
{
	struct waitqueue *waitq = &current->proc->wq;
	void *ulock = (void *)regs->r[ARG_REG + 1];

	if (!access_ok(ulock, sizeof(uint32_t)))
		return -EFAULT;

	__wakeup(waitq, ulock);
	return 0;
}
