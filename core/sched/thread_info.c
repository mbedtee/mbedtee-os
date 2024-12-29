// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Get current thread information.
 */

#include <thread.h>
#include <process.h>

#include "sched_priv.h"

/*
 * Get the thread by TID,
 * increase the reference counter.
 * return the thread structure
 */
struct thread *thread_get(pid_t id)
{
	struct sched *s = sched_get(id);

	return s ? s->thread : NULL;
}

/*
 * Put the thread by thread structure,
 * decrease the reference counter.
 */
void thread_put(struct thread *t)
{
	if (t)
		sched_put(t->sched);
}

bool thread_overflow(struct thread *t)
{
	return sched_overflow(t->sched);
}
