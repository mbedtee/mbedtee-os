// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Semaphore implementation
 */

#include <defs.h>
#include <sched.h>
#include <errno.h>
#include <trace.h>
#include <thread.h>
#include <lockdep.h>
#include <interrupt.h>
#include <semaphore.h>

static inline void __set_owner(struct thread *t,
	struct semaphore *s)
{
	s->owner_id = t->id;

	/* make sure the owner_id update is visible to others */
	smp_mb();
}

static inline void __clear_owner(struct semaphore *s)
{
	s->owner_id = 0;
}

void sema_init(struct semaphore *s, char limit)
{
	if ((!s) || (limit == 0))
		return;

	s->limit = limit;
	s->lock = LOCKVAL_INIT(limit);
	s->owner_id = 0;
	waitqueue_init(&s->wq);
}

void down(struct semaphore *s)
{
	struct thread *t = current;

	if (s == NULL)
		return;

	do {
		if (!atomic_read_x(&s->lock.val)) {
			sched_inherit_prio(t->sched, s->owner_id);
			wait(&s->wq);
		}
	} while (arch_semaphore_acquire(&s->lock));

	__set_owner(t, s);
}

void up(struct semaphore *s)
{
	pid_t owner = 0;

	if (s == NULL)
		return;

	owner = s->owner_id;

	__clear_owner(s);

	while (arch_semaphore_release(&s->lock, &s->limit))
		;

	wakeup(&s->wq);
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
	if (!s)
		return -EINVAL;

	if (!atomic_read_x(&s->lock.val))
		return true;

	if (likely(arch_semaphore_acquire(&s->lock) == 0)) {
		__set_owner(current, s);
		return false;
	}

	return true;
}
