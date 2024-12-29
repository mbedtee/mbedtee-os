/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#ifndef _WORKQUEUE_H
#define _WORKQUEUE_H

#include <list.h>
#include <atomic.h>
#include <percpu.h>
#include <tevent.h>

#define WORKQUEUE_NAME_LEN (30)

struct workqueue {
	/* workqueue scheduler priority */
	int prio;
	/* workqueue scheduler policy */
	int policy;
	/* list of pending delay works */
	struct list_head dws;
	struct waitqueue wait_q;
	struct list_head workers;
	char state;
	struct spinlock lock;
	char name[WORKQUEUE_NAME_LEN];
};

struct work {
	/* entry in workqueue, wq internal */
	struct list_head node;

	/* belongs to which worker, wq internal */
	void *worker;

	/* for caller, assigne func and data */
	void (*func)(struct work *w);

	void *data;

	/* this struct is busy or idle */
	struct atomic_num busy;
};

struct delayed_work {
	/* on which cpu or unbind? wq internal */
	int cpu;

	struct work w;
	/* timer event, wq internal */
	struct tevent timer;
	/* belongs to which workqueue, wq internal */
	struct workqueue *wq;
	/* entry in workqueue, wq internal */
	struct list_head node;
};

typedef void (*work_func_t)(struct work *);

#define INIT_WORK(__w, __f)								\
	do {												\
		INIT_LIST_HEAD(&(__w)->node);					\
		(__w)->busy = (struct atomic_num){0};			\
		(__w)->func = __f;								\
		(__w)->worker = NULL;							\
	} while (0)

#define INIT_DELAYED_WORK(__dw, __f)					\
	do {												\
		INIT_WORK(&(__dw)->w, __f);						\
		INIT_LIST_HEAD(&(__dw)->node);					\
		tevent_init(&(__dw)->timer, NULL, NULL);		\
		(__dw)->wq = NULL;								\
		(__dw)->cpu = 0;								\
	} while (0)

#define DEFAULT_WORK(__w, __f) {						\
	LIST_HEAD_INIT((__w).node), NULL,					\
	__f, NULL, {0},										\
}

#define DEFAULT_DELAYED_WORK(__dw, __f) {				\
	0,													\
	DEFAULT_WORK((__dw).w, __f),						\
	DEFAULT_TEVENT((__dw).timer), NULL,					\
	LIST_HEAD_INIT((__dw).node),						\
}

#define DECLARE_WORK(_w, _f)							\
	struct work _w = DEFAULT_WORK(_w, _f)

#define DECLARE_DELAYED_WORK(_dw, _f)					\
	struct delayed_work _dw = DEFAULT_DELAYED_WORK(_dw, _f)

void workqueue_init(void);
struct workqueue *create_workqueue(const char *fmt, ...);
void destroy_workqueue(struct workqueue *wq);
void flush_workqueue(struct workqueue *wq);
void workqueue_setscheduler(struct workqueue *wq, int policy, int prio);
void worker_down(void);

bool queue_work(struct workqueue *wq, struct work *w);
bool queue_delayed_work(struct workqueue *wq, struct delayed_work *dw,
	useconds_t usecs);
bool schedule_work(struct work *w);
bool schedule_highpri_work(struct work *w);
bool schedule_delayed_work(struct delayed_work *dw, useconds_t usecs);

bool queue_work_on(int cpu, struct workqueue *wq, struct work *w);
bool queue_delayed_work_on(int cpu, struct workqueue *wq,
	struct delayed_work *dw, useconds_t usecs);
bool schedule_work_on(int cpu, struct work *w);
bool schedule_highpri_work_on(int cpu, struct work *w);
bool schedule_delayed_work_on(int cpu, struct delayed_work *dw, useconds_t usecs);

bool flush_work(struct work *w);
bool flush_delayed_work(struct delayed_work *dw);

/*
 * return true if this function cancelled this work,
 * otherwise return false (e.g. work already been picked or still be handling).
 */
bool cancel_work(struct work *w);

bool cancel_work_sync(struct work *w);

/*
 * return true if this function cancelled this delayed_work,
 * otherwise return false (e.g. delayed_work already been picked or still be handling).
 */
bool cancel_delayed_work(struct delayed_work *dw);

bool cancel_delayed_work_sync(struct delayed_work *dw);

/*
 * return true if this function modified the timer,
 * or started a new delayed_work
 * otherwise return false (e.g. already been queued).
 */
bool mod_delayed_work_on(int cpu, struct workqueue *wq,
	struct delayed_work *dw, useconds_t usecs);
bool mod_delayed_work(struct workqueue *wq,
	struct delayed_work *dw, useconds_t usecs);

/*
 * almost same as the schedule_work()/schedule_work_on(), the only difference is:
 * __schedule_work_xx() only pick the worker, does not create new worker,
 * while the schedule_work_xx() creates new worker if there is no idle worker.
 */
bool __schedule_work(struct work *w);
bool __schedule_work_on(int cpu, struct work *w);
bool __schedule_highpri_work_on(int cpu, struct work *w);
bool __schedule_delayed_work(struct delayed_work *dw, useconds_t usecs);
bool __schedule_delayed_work_on(int cpu, struct delayed_work *dw, useconds_t usecs);
bool __mod_delayed_work(struct delayed_work *dw, useconds_t usecs);
bool __mod_delayed_work_on(int cpu, struct delayed_work *dw, useconds_t usecs);

#endif
