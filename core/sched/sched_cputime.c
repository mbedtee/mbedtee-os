// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * record the pthread/process's cputime
 */

#include <timer.h>
#include <trace.h>
#include <thread.h>
#include <sched.h>

#include "sched_priv.h"
#include "sched_record.h"

void __sched_thread_cputime(void *t, struct timespec *tval)
{
	struct sched *dst = sched_of(t);

	cycles_to_time(dst->overall, tval);
}

int sched_thread_cputime(pid_t tid, struct timespec *tval)
{
	unsigned long flags = 0;
	struct sched_priv *sp = NULL;
	struct sched *dst = sched_get_lock(tid, &flags);

	tval->tv_sec = tval->tv_nsec = 0;

	if (dst == NULL)
		return -ESRCH;

	sp = dst->sp;

	spin_lock(&sp->lock);

	if (dst == sp->curr)
		sched_record_curr(dst);

	cycles_to_time(dst->overall, tval);

	spin_unlock(&sp->lock);

	sched_put_lock(dst, flags);

	return 0;
}

int sched_process_cputime(pid_t tid, struct timespec *tval)
{
	unsigned long flags = 0;
	struct thread *thd = NULL;
	struct timespec sval;
	struct process *proc = process_get(tid);

	tval->tv_sec = tval->tv_nsec = 0;

	if (proc == NULL)
		return -ESRCH;

	spin_lock_irqsave(&proc->slock, flags);
	list_for_each_entry(thd, &proc->threads, node) {
		sval.tv_sec = sval.tv_nsec = 0;
		sched_thread_cputime(thd->id, &sval);
		timespecadd(&sval, tval, tval);
	}
	timespecadd(tval, &proc->runtime, tval);
	spin_unlock_irqrestore(&proc->slock, flags);

	process_put(proc);
	return 0;
}
