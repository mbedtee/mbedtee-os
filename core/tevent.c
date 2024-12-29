// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * timer events framework
 */

#include <timer.h>
#include <tevent.h>
#include <trace.h>
#include <kmalloc.h>
#include <sched.h>
#include <spinlock.h>
#include <percpu.h>

#include <generated/autoconf.h>

#define tevent_active(t) (!rb_empty(&(t)->node))

/*
 * percpu tevent information
 */
static struct percpu_ti {
	struct spinlock lock;
	uint16_t nrevents;
	struct tevent *curr;
	struct rb_node *tevents;
} __percpu_ti[CONFIG_NR_CPUS] = {0};

static inline struct percpu_ti *percpu_ti(void)
{
	return &__percpu_ti[percpu_id()];
}

void tevents_init(void)
{
	struct percpu_ti *ti = percpu_ti();

	ti->curr = NULL;
	ti->tevents = NULL;
	ti->nrevents = 0;

	spin_lock_init(&ti->lock);
}

static inline intptr_t tevent_rbadd_cmp(
	const struct rb_node *n, const struct rb_node *ref)
{
	struct tevent *t = rb_entry_of(n, struct tevent, node);
	struct tevent *reft = rb_entry_of(ref, struct tevent, node);

	if (timespeccmp(&t->expire, &reft->expire, <)) {
		/*
		 * put the current node into queue again,
		 * due to there is a newer one inserted
		 */
		reft->ticking = false;
		return -1;
	}

	return 1;
}

static inline bool tevent_queue_add(
	struct percpu_ti *ti,
	struct tevent *t)
{
	t->ti = ti;

	ti->nrevents++;

	rb_add(&t->node, &ti->tevents, tevent_rbadd_cmp);

	return &t->node == rb_first(ti->tevents);
}

static inline void tevent_queue_del(
	struct percpu_ti *ti,
	struct tevent *t)
{
	rb_del(&t->node, &ti->tevents);
	t->ticking = false;
	ti->nrevents--;
}

void tevent_init(struct tevent *t,
	tevent_handler handler, void *data)
{
	if (t) {
		rb_node_init(&t->node);
		spin_lock_init(&t->lock);
		t->handler = handler;
		t->data = data;
		t->ticking = false;
		timespecclear(&t->expire);
		t->ti = NULL;
	}
}

static void __tevent_trigger_next(
	struct tevent *t,
	struct timespec *next)
{
	uint64_t cycles = 0, minim = CYCLES_PER_MSECS;

	cycles = time_to_cycles(next);

	trigger_next(max(cycles, minim));

	t->ticking = true;
}

/*
 * safe way to start a timer
 * even if multi-user@different-CPU using this timer
 */
void tevent_start(struct tevent *t, struct timespec *time)
{
	struct timespec now;
	unsigned long flags = 0;
	struct percpu_ti *ti = NULL;

	assert(!INVALID_TIMESPEC(time));

	spin_lock_irqsave(&t->lock, flags);
	if (!tevent_active(t)) {
		ti = percpu_ti();
		read_time(&now);

		timespecadd(&now, time, &t->expire);

		spin_lock(&ti->lock);
		if (tevent_queue_add(ti, t) == true)
			__tevent_trigger_next(t, time);
		spin_unlock(&ti->lock);
	}
	spin_unlock_irqrestore(&t->lock, flags);
}

/*
 * return true if it stopped this event,
 * otherwise return false (e.g. already been stopped, or not started).
 */
int tevent_stop(struct tevent *t)
{
	int ret = false;
	struct percpu_ti *ti = NULL;
	unsigned long flags = 0;

	do  {
		spin_lock_irqsave(&t->lock, flags);

		ti = t->ti;

		if (tevent_active(t)) {
			spin_lock(&ti->lock);
			if (tevent_active(t)) {
				tevent_queue_del(ti, t);
				ret = true;
			}
			spin_unlock(&ti->lock);
		}
		spin_unlock_irqrestore(&t->lock, flags);
	} while (0);

	return ret;
}

void tevent_renew(struct tevent *t, struct timespec *time)
{
	struct timespec now;
	unsigned long flags = 0;
	struct percpu_ti *ti = NULL;
	struct percpu_ti *cti = NULL;

	spin_lock_irqsave(&t->lock, flags);

	ti = t->ti;
	cti = percpu_ti();

	assert(!INVALID_TIMESPEC(time));

	do {
		if (tevent_active(t)) {
			spin_lock(&ti->lock);
			if (ti == t->ti)
				tevent_queue_del(ti, t);
			spin_unlock(&ti->lock);
		}
	} while (ti && (ti != cti) && (t == ti->curr));

	ti = percpu_ti();
	read_time(&now);

	timespecadd(&now, time, &t->expire);

	spin_lock(&ti->lock);
	if (tevent_queue_add(ti, t) == true)
		__tevent_trigger_next(t, time);
	spin_unlock(&ti->lock);

	spin_unlock_irqrestore(&t->lock, flags);
}

void tevent_isr(void)
{
	struct percpu_ti *ti = percpu_ti();
	struct tevent *t = NULL;
	struct timespec now, left;

	spin_lock(&ti->lock);

	while ((t = rb_first_entry(ti->tevents,
			struct tevent, node)) != NULL) {

		read_time(&now);
		timespecsub(&t->expire, &now, &left);

		if (timespeccmp(&left, &((struct timespec){0, 1000L}), >)) {
			if (t->ticking == false)
				__tevent_trigger_next(t, &left);
			break;
		}

		ti->curr = t;
		tevent_queue_del(ti, t);
		spin_unlock(&ti->lock);
		t->handler(t);
		spin_lock(&ti->lock);
		ti->curr = NULL;
	}

	spin_unlock(&ti->lock);
}

/*
 * For CPU Hot-Plug
 * migrating the tevents to a live CPU
 */
void tevent_migrating(void)
{
	struct tevent *t = NULL;
	int cpu = sched_pick_mostidle_cpu();
	struct percpu_ti *src = percpu_ti();
	struct percpu_ti *dst = &__percpu_ti[cpu];

	while ((t = rb_first_entry(src->tevents,
			struct tevent, node)) != NULL) {
		spin_lock(&t->lock);
		if (tevent_active(t) && (t->ti == src)) {
			spin_lock(&src->lock);
			tevent_queue_del(src, t);
			spin_unlock(&src->lock);

			spin_lock(&dst->lock);
			tevent_queue_add(dst, t);
			spin_unlock(&dst->lock);
		}
		spin_unlock(&t->lock);
	}
}
