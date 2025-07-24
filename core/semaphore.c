// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Semaphore implementation
 */

#include <defs.h>
#include <sched.h>
#include <errno.h>
#include <trace.h>
#include <thread.h>
#include <lockdep.h>
#include <interrupt.h>
#include <ksemaphore.h>

static inline void __set_owner(struct thread *t,
	struct semaphore *s)
{
	/* Publish owner_id after prior semaphore state updates. */
	smp_store_mb(&s->owner_id, t->id);
}

static inline void __clear_owner(struct semaphore *s)
{
	s->owner_id = 0;
}

void sema_init(struct semaphore *s, unsigned int limit)
{
	if (!s || limit == 0)
		return;

	s->limit = limit;
	s->lock = LOCKVAL_INIT(limit);
	s->owner_id = 0;
	spin_lock_init(&s->slock);
	waitqueue_init(&s->wq);
}

void down(struct semaphore *s)
{
	unsigned long flags = 0;
	struct thread *t = current;

	if (!s)
		return;

	spin_lock_irqsave(&s->slock, flags);

	do {
		if (smp_load_acquire(&s->lock.val) == 0) {
			spin_unlock(&s->slock);
			sched_inherit_prio(t->sched, s->owner_id);
			wait_event(&s->wq, smp_load_acquire(&s->lock.val) > 0);
			spin_lock(&s->slock);
		}
	} while (arch_semaphore_acquire(&s->lock));

	__set_owner(t, s);

	spin_unlock_irqrestore(&s->slock, flags);
}

int down_interruptible(struct semaphore *s)
{
	unsigned long flags = 0;
	long wret = 0;
	struct thread *t = current;

	if (!s)
		return -EINVAL;

	spin_lock_irqsave(&s->slock, flags);

	do {
		if (smp_load_acquire(&s->lock.val) == 0) {
			spin_unlock(&s->slock);
			sched_inherit_prio(t->sched, s->owner_id);
			wret = wait_event_interruptible(&s->wq,
				smp_load_acquire(&s->lock.val) > 0);
			spin_lock(&s->slock);

			if (wret == -EINTR && smp_load_acquire(&s->lock.val) == 0) {
				spin_unlock_irqrestore(&s->slock, flags);
				return -EINTR;
			}
		}
	} while (arch_semaphore_acquire(&s->lock));

	__set_owner(t, s);

	spin_unlock_irqrestore(&s->slock, flags);
	return 0;
}

void up(struct semaphore *s)
{
	unsigned long flags = 0;
	pid_t owner = 0;

	if (!s)
		return;

	spin_lock_irqsave(&s->slock, flags);

	owner = s->owner_id;

	__clear_owner(s);

	while (arch_semaphore_release(&s->lock, &s->limit))
		;

	wakeup(&s->wq);

	spin_unlock_irqrestore(&s->slock, flags);

	sched_resume_prio(owner);
}

/*
 * down_trylock - try to acquire the semaphore, without waiting
 * @sem: the semaphore to be acquired
 *
 * Returns 0 if the semaphore has been acquired successfully
 * or 1 if it cannot be acquired.
 */
int down_trylock(struct semaphore *s)
{
	unsigned long flags = 0;
	int ret = 1;
	struct thread *t = current;

	if (!s)
		return -EINVAL;

	spin_lock_irqsave(&s->slock, flags);

	if (smp_load_acquire(&s->lock.val) != 0 &&
		likely(arch_semaphore_acquire(&s->lock) == 0)) {
		__set_owner(t, s);
		ret = 0;
	}

	spin_unlock_irqrestore(&s->slock, flags);

	return ret;
}
