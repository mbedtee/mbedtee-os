// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Mutex implementation
 */
#include <defs.h>
#include <errno.h>
#include <trace.h>
#include <mutex.h>
#include <sched.h>
#include <thread.h>
#include <lockdep.h>
#include <interrupt.h>

static inline void mutex_set_owner(
	struct thread *t,
	struct mutex *m)
{
	/* Publish owner_id after lock acquisition/meta updates. */
	smp_store_mb(&m->owner_id, t->id);

	if (list_empty(&m->node))
		list_add_tail(&m->node, &t->mutexs);
}

static inline void mutex_clear_owner(struct mutex *m)
{
	list_del(&m->node);
	m->owner_id = 0;
}

void mutex_init(struct mutex *m)
{
	if (m) {
		m->rc = 0;
		m->owner_id = 0;
		m->type = MUTEX_NORMAL;
		m->lock = LOCKVAL_INIT(0);
		spin_lock_init(&m->slock);
		INIT_LIST_HEAD(&m->node);
		waitqueue_init(&m->waitq);
	}
}

void mutex_init_recursive(struct mutex *m)
{
	if (m) {
		m->rc = 0;
		m->owner_id = 0;
		m->type = MUTEX_RECURSIVE;
		m->lock = LOCKVAL_INIT(0);
		spin_lock_init(&m->slock);
		INIT_LIST_HEAD(&m->node);
		waitqueue_init(&m->waitq);
	}
}

void mutex_lock(struct mutex *m)
{
	unsigned long flags = 0;
	struct thread *t = current;

	if (!m)
		return;

	spin_lock_irqsave(&m->slock, flags);

	do {
		if (smp_load_acquire(&m->lock.val)) {
			if (m->type == MUTEX_RECURSIVE) {
				if (m->owner_id == t->id)
					goto out;
			}

			spin_unlock(&m->slock);
			sched_inherit_prio(t->sched, m->owner_id);
			wait_event(&m->waitq, !smp_load_acquire(&m->lock.val));
			spin_lock(&m->slock);
		}
	} while (arch_atomic_tryacquire(&m->lock));

out:
	m->rc++;
	mutex_set_owner(t, m);
	spin_unlock_irqrestore(&m->slock, flags);
}

int mutex_lock_interruptible(struct mutex *m)
{
	unsigned long flags = 0;
	long wret = 0;
	struct thread *t = current;

	if (!m)
		return -EINVAL;

	spin_lock_irqsave(&m->slock, flags);

	do {
		if (smp_load_acquire(&m->lock.val)) {
			if (m->type == MUTEX_RECURSIVE) {
				if (m->owner_id == t->id)
					goto out;
			}

			spin_unlock(&m->slock);
			sched_inherit_prio(t->sched, m->owner_id);
			wret = wait_event_interruptible(&m->waitq,
				!smp_load_acquire(&m->lock.val));
			spin_lock(&m->slock);

			if (wret == -EINTR && smp_load_acquire(&m->lock.val)) {
				spin_unlock_irqrestore(&m->slock, flags);
				return -EINTR;
			}
		}
	} while (arch_atomic_tryacquire(&m->lock));

out:
	m->rc++;
	mutex_set_owner(t, m);
	spin_unlock_irqrestore(&m->slock, flags);
	return 0;
}

void mutex_unlock(struct mutex *m)
{
	unsigned long flags = 0;

	if (!m)
		return;

	spin_lock_irqsave(&m->slock, flags);

	assert(m->rc > 0);

	if (--m->rc == 0) {
		mutex_clear_owner(m);
		arch_atomic_release(&m->lock);
		wakeup(&m->waitq);
	}

	spin_unlock_irqrestore(&m->slock, flags);
}

int mutex_trylock(struct mutex *m)
{
	unsigned long flags = 0;
	int ret = 0;
	struct thread *t = current;

	spin_lock_irqsave(&m->slock, flags);

	if (likely(arch_atomic_tryacquire(&m->lock) == 0) ||
		((m->type == MUTEX_RECURSIVE) && (m->owner_id == t->id))) {
		m->rc++;
		mutex_set_owner(t, m);
		ret = true;
	}

	spin_unlock_irqrestore(&m->slock, flags);

	return ret;
}

void mutex_destroy(struct mutex *m)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&m->slock, flags);

	if (smp_load_acquire(&m->lock.val))
		EMSG("The mutex is locked\n");

	wakeup(&m->waitq);

	spin_unlock_irqrestore(&m->slock, flags);

	waitqueue_flush(&m->waitq);
}

static void mutex_cleanup_t(struct thread *t)
{
	struct mutex *m = NULL, *n = NULL;

	list_for_each_entry_safe(m, n, &t->mutexs, node) {
		IMSG("%s unlocking @ %p\n", t->name, m);
		mutex_unlock(m);
	}
}
DECLARE_THREAD_CLEANUP_HIGH(mutex_cleanup_t);
