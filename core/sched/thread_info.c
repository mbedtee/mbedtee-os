// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Get current thread information.
 */

#include <thread.h>
#include <process.h>
#include <sections.h>

#include "sched_priv.h"

/*
 * Invoke all registered thread cleanup callbacks
 */
void thread_cleanup_run(struct thread *t)
{
	thread_cleanup_func_t func = NULL;
	unsigned long ptr = 0;
	unsigned long start = __thread_cleanup_start();
	unsigned long end = __thread_cleanup_end();

	for (ptr = start; ptr < end; ptr += sizeof(ptr)) {
		func = *(thread_cleanup_func_t *)ptr;
		if (func)
			func(t);
	}
}

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
