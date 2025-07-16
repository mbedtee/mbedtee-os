/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * timer events framework
 */

#ifndef _TEVENT_H
#define _TEVENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <rbtree.h>
#include <kmalloc.h>
#include <spinlock.h>

struct tevent {
	struct rb_node node;
	struct timespec expire;
	void (*handler)(struct tevent *t);
	void *data;
	void *ti;
	bool ticking;
	struct spinlock lock;
};

typedef void (*tevent_handler)(struct tevent *);

#define DEFAULT_TEVENT(t) {             \
	RB_INIT_NODE((t).node),             \
	{0}, NULL, NULL,                    \
	NULL, false, SPIN_LOCK_INIT(0)      \
}

/*
 * Initialize percpu tevent manager information
 */
void tevents_init(void);

/*
 * Initialize tevent entity
 */
void tevent_init(struct tevent *event, tevent_handler handler, void *data);

/*
 * Start a tevent entity
 */
void tevent_start(struct tevent *event, struct timespec *time);

/*
 * Add the tevent to the target CPU's timer list.
 * The tevent may not be triggered or handled immediately,
 * because the current CPU may not be able to set another CPU's timer hardware.
 */
void tevent_start_on(struct tevent *t, struct timespec *time, int cpu);

/*
 * Renew a tevent entity
 */
void tevent_renew(struct tevent *event, struct timespec *time);

/*
 * Return true if the event was stopped,
 * false otherwise (e.g. it was already stopped).
 */
int tevent_stop(struct tevent *event);

static inline struct tevent *tevent_alloc(
	tevent_handler handler, void *data)
{
	struct tevent *t = kmalloc(sizeof(*t));

	if (t)
		tevent_init(t, handler, data);

	return t;
}

static inline void tevent_free(struct tevent *t)
{
	unsigned long flags = 0;

	if (smp_load_acquire(&t->lock.lock.val))
		EMSG("tevent is still locked\n");

	/* final confirm */
	spin_lock_irqsave(&t->lock, flags);
	spin_unlock_irqrestore(&t->lock, flags);

	kfree(t);
}

/*
 * For CPU Hot-Plug
 * Take over the tevents of the destination CPU.
 */
void tevent_takeover(int cpu_id);
void tevent_migrating(void);

void tevent_isr(void);

#ifdef __cplusplus
}
#endif
#endif
