/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * timer events framework
 */

#ifndef _TEVENT_H
#define _TEVENT_H

#include <time.h>
#include <rbtree.h>
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
 * Renew a tevent entity
 */
void tevent_renew(struct tevent *event, struct timespec *time);

/*
 * return true if it stopped this event,
 * otherwise return false (e.g. already stopped).
 */
int tevent_stop(struct tevent *event);

/*
 * For CPU Hot-Plug
 * take over the tevents of the dest CPU
 */
void tevent_takeover(int cpu_id);
void tevent_migrating(void);

void tevent_isr(void);

#endif
