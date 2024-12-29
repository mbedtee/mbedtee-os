// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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
	m->owner_id = t->id;
	list_add_tail(&m->node, &t->mutexs);

	/* make sure the owner_id update is visible to others */
	smp_mb();
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
		INIT_LIST_HEAD(&m->node);
		waitqueue_init(&m->waitq);
	}
}

void mutex_lock(struct mutex *m)
{
	struct thread *t = current;

	if (m == NULL)
		return;

	do {
		if (atomic_read_x(&m->lock.val)) {
			if (m->type == MUTEX_RECURSIVE) {
				if (m->owner_id == t->id) {
					m->rc++;
					return;
				}
			}
			/*sched_inherit_prio(t->sched, m->owner_id);*/
			wait_event(&m->waitq, !atomic_read_x(&m->lock.val));
		}
	} while (arch_atomic_tryacquire(&m->lock));

	m->rc++;
	mutex_set_owner(t, m);
}

void mutex_unlock(struct mutex *m)
{
	if (m == NULL)
		return;

	assert(m->rc > 0);

	if (--m->rc == 0) {
		mutex_clear_owner(m);
		arch_atomic_release(&m->lock);
		wakeup(&m->waitq);
	}
}

int mutex_trylock(struct mutex *m)
{
	if (likely(arch_atomic_tryacquire(&m->lock) == 0)) {
		m->rc++;
		mutex_set_owner(current, m);
		return true;
	}

	if (m->type == MUTEX_RECURSIVE) {
		if (m->owner_id == current->id) {
			m->rc++;
			return true;
		}
	}

	return false;
}

void mutex_destroy(struct mutex *m)
{
	if (m && atomic_read_x(&m->lock.val))
		EMSG("The mutex is locked\n");
}
