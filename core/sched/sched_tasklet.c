// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * tasklets for handling the bottom half of the interrupts serialized,
 * with interrupt enabled and critical priority (percpu tasklet)
 */

#include <device.h>
#include <percpu.h>
#include <sched.h>
#include <list.h>
#include <kthread.h>
#include <interrupt.h>
#include <trace.h>
#include <delay.h>
#include <barrier.h>
#include <tasklet.h>
#include <tevent.h>

#include "sched_list.h"
#include "sched_priv.h"

#define TASKLET_IDLE  0
#define TASKLET_SCHED 1
#define TASKLET_RUN   2
#define TASKLET_KILL  3

#define tasklet_wait_done(t) \
	do { } while (atomic_read(&t->state) == TASKLET_RUN)
#define tasklet_wait_idle(t) \
	do { } while (atomic_read(&t->state) != TASKLET_IDLE)

void tasklet_init(struct tasklet *t,
	void (*func)(unsigned long),
	unsigned long data)
{
	if (t && func) {
		INIT_LIST_HEAD(&t->node);
		atomic_set(&t->state, TASKLET_IDLE);
		atomic_set(&t->disable, false);
		t->func = func;
		t->data = data;
	}
}

void tasklet_schedule(struct tasklet *t)
{
	unsigned long flags = 0;
	struct sched_priv *sp = NULL;
	struct sched *taskletd = NULL;
	void *ctx = NULL;

	local_irq_save(flags);

	sp = sched_priv();
	taskletd = sp->taskletd;

	if (sp->taskletd &&	(atomic_read(&t->state)
			== TASKLET_IDLE)) {
		ctx = sp->pc->int_ctx;

		atomic_set(&t->state, TASKLET_SCHED);

		if (list_empty(&t->node))
			list_add_tail(&t->node, &sp->tasklets);

		/*
		 * If in an interrupt context, taskletd will be executed
		 * immediately with its own stack after quit INT boundary.
		 *
		 * If not, raise the softint to execute taskletd ASAP.
		 *
		 * Linux softint borrows the current interrupted thread's stack
		 * when exiting IRQ boundary, unlike the Linux softint execution,
		 * TEE will use the taskletd own stack(context) instead of the
		 * interrupted thread's stack.
		 */
		if (sp->curr != taskletd) {
			wakeup(&taskletd->thread->wait_q);
			if (ctx == NULL)
				ipi_call_sched(sp->pc->id);
		}

		if ((sp->curr != taskletd) && ctx)
			__sched_exec_specified(sp, taskletd, ctx);
	}
	local_irq_restore(flags);
}

void tasklet_disable(struct tasklet *t)
{
	atomic_inc(&t->disable);
	tasklet_wait_done(t);
}

void tasklet_enable(struct tasklet *t)
{
	atomic_dec(&t->disable);
}

void tasklet_kill(struct tasklet *t)
{
	unsigned long flags = 0;

	tasklet_wait_done(t);

	if (atomic_set_return(&t->state,
		TASKLET_KILL) == TASKLET_RUN)
		tasklet_wait_idle(t);
	else
		atomic_set(&t->state, TASKLET_IDLE);

	local_irq_save(flags);
	list_del(&t->node);
	local_irq_restore(flags);
}

static struct tasklet *tasklet_pick_next(
	struct sched_priv *sp)
{
	struct tasklet *t = NULL;
	unsigned long flags = 0;

	local_irq_save(flags);

	if (sp == sched_priv()) {
		t = list_first_entry_or_null(&sp->tasklets,
				struct tasklet, node);
		if (t)
			list_del(&t->node);
	}

	local_irq_restore(flags);
	return t;
}

static void tasklet_working(struct sched_priv *sp)
{
	struct tasklet *t = NULL;

	while ((t = tasklet_pick_next(sp)) != NULL) {
		if (atomic_read(&t->disable) <= 0) {
			atomic_set(&t->state, TASKLET_RUN);
			t->func(t->data);
			atomic_set(&t->state, TASKLET_IDLE);
		}
	}
}

void sched_tasklet_routine(void *data)
{
	struct sched_priv *sp = data;
	struct thread *t = current;
	struct sched *s = sched_of(t);

	do {
		wait_event(&t->wait_q, (!list_empty(&sp->tasklets)) ||
				(sp != s->sp) || (s != sp->taskletd));
		tasklet_working(sp);
	} while ((sp == s->sp) && (s == sp->taskletd));
}

void sched_tasklet_init(struct sched_priv *sp)
{
	pid_t id = -1;
	struct sched_gd *gd = sched_gd();
	struct sched_param p = {.sched_priority = SCHED_PRIO_MAX - 1};

	INIT_LIST_HEAD(&sp->tasklets);

	id = kthread_create_on(sched_tasklet_routine,
			sp, sp->pc->id, "taskletd");
	if (id < 0) {
		EMSG("kthread_create failed %d\n", id);
		cpu_set_error();
	}

	sp->taskletd = gd->scheds[id];

	/* taskletd is the top priority - 1 */
	sched_setscheduler(id, SCHED_FIFO, &p);
	sched_ready(id);
}

/*
 * For CPU Hot-Plug
 * set the exit condition for taskletd routine
 */
void sched_tasklet_deinit(struct sched_priv *sp)
{
	if (sp->taskletd) {
		struct thread *t = sp->taskletd->thread;

		if (!list_empty(&sp->tasklets))
			IMSG("tasklets not empty\n");

		tasklet_working(sp);

		wakeup(&t->wait_q);

		sp->taskletd = NULL;
	}
}
