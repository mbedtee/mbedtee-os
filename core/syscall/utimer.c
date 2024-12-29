// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * posix timer for userspace
 */

#include <errno.h>
#include <trace.h>
#include <device.h>
#include <thread.h>
#include <string.h>
#include <buddy.h>
#include <sched.h>
#include <kmalloc.h>
#include <mutex.h>
#include <prng.h>
#include <timer.h>
#include <ktime.h>
#include <ksignal.h>
#include <sys/pthread.h>
#include <__pthread.h>

static SPIN_LOCK(tlock);
static struct rb_node *utimers;

struct utimer {
	timer_t id;
	clockid_t clockid;
	/* node at timer global rbtree */
	struct rb_node node;
	/* node at process's timer list, for cleanup only */
	struct list_head pnode;
	struct tevent tevent;
	struct itimerspec ts;
	struct timespec newval;
	struct sigevent evp;
	pthread_attr_t attr;
	struct work w;
	int overrun;
	pid_t pid;
	pid_t evplasttid;
	short refc;
	struct spinlock lock;
};

static inline intptr_t _timer_rbfind_cmp(
	const void *key, const struct rb_node *ref)
{
	struct utimer *vm = rb_entry_of(ref, struct utimer, node);

	if ((timer_t)key == vm->id)
		return 0;

	return ((timer_t)key < vm->id) ? -1 : 1;
}

static struct utimer *timer_find(timer_t id)
{
	return rb_entry(rb_find((void *)id,
			utimers, _timer_rbfind_cmp),
			struct utimer, node);
}

static inline struct utimer *timer_lookup(timer_t id)
{
	pid_t pid = 0;
	struct utimer *t = timer_find(id);

	if (t == NULL)
		return NULL;

	pid = current->proc->id;

	if ((pid == 0) || (t->pid == pid))
		return t;

	return NULL;
}

static inline timer_t timer_id_assign(pid_t tid)
{
	timer_t id = 0;

	do {
		prng(&id, sizeof(id));
		id <<= 16;
		id |= tid;
	} while (timer_find(id) != NULL);

	return id;
}

static inline struct utimer *timer_get_lock(
	timer_t timerid, unsigned long *flags)
{
	struct utimer *t = NULL;
	unsigned long f = 0;

	spin_lock_irqsave(&tlock, f);

	t = timer_lookup(timerid);
	if (t == NULL) {
		spin_unlock_irqrestore(&tlock, f);
		return NULL;
	}

	spin_lock(&t->lock);

	spin_unlock(&tlock);

	*flags = f;

	return t;
}

static inline void timer_put_lock(struct utimer *t,
	unsigned long flags)
{
	spin_unlock_irqrestore(&t->lock, flags);
}

static void timer_worker(struct work *w)
{
	int ret = -1, to_free = false;
	struct process *proc = NULL;
	struct timespec tval;
	unsigned long flags = 0;
	struct utimer *t = container_of(w, struct utimer, w);
	timer_t id = t->id;
	int evpsigtimer = 0;

	spin_lock_irqsave(&t->lock, flags);

	/* process exiting ? */
	proc = process_get(t->pid);
	if (proc == NULL) {
		t->refc--;
		goto out;
	}

	if (t->evp.sigev_notify == SIGEV_THREAD) {
		struct thread *lastthd = thread_get(t->evplasttid);

		if (!lastthd) {
			ret = pthread_kcreate(proc,
				t->evp.sigev_notify_attributes ? &t->attr : NULL,
				(pthread_func_t)t->evp.sigev_notify_function,
				t->evp.sigev_value.sival_ptr);
			if (ret > 0) {
				t->evplasttid = ret;
				sched_ready(ret);
				t->overrun--;
			}
		} else {
			thread_put(lastthd);
		}
	} else {
		int signo = t->evp.sigev_signo;

		if (signo == SIGTIMER) {
			evpsigtimer = signo;
			signo = SIGALRM;
		}

		ret = sigenqueue(t->pid, signo, SI_TIMER,
				t->evp.sigev_value, false);
		if (ret == 0)
			t->overrun--;
	}

	if (timespecisset(&t->newval)) {
		tevent_start(&t->tevent, &t->newval);
		timespecclear(&t->newval);
	} else if (timespecisset(&t->ts.it_interval)) {
		tval = t->ts.it_interval;
		/* resource is not enough, force slow down the timer */
		if ((ret < 0) && (tval.tv_sec < 10)) {
			/* min 5ms, max 10s */
			unsigned long usecs = time_to_usecs(&tval);

			usecs = t->overrun * max(usecs, 5000ul);
			usecs_to_time(min(usecs, MICROSECS_PER_SEC * 10), &tval);
		}
		timespecadd(&t->ts.it_value, &tval, &t->ts.it_value);
		tevent_start(&t->tevent, &tval);
	} else {
		t->refc--;
	}

out:
	to_free = t->refc == 0;
	spin_unlock_irqrestore(&t->lock, flags);

	if (to_free)
		kfree(t);

	if (evpsigtimer)
		timer_delete(id);

	process_put(proc);
}

static void timer_event(struct tevent *e)
{
	struct utimer *t = container_of(e, struct utimer, tevent);

	t->overrun++;

	schedule_work(&t->w);
}

static bool __timer_del(struct utimer *t)
{
	timespecclear(&t->newval);
	t->ts.it_interval = t->newval;
	if (tevent_stop(&t->tevent))
		t->refc--;

	return t->refc == 0;
}

int timer_delete(timer_t timerid)
{
	struct utimer *t = NULL;
	unsigned long flags = 0;
	bool to_free = false;

	local_irq_save(flags);

	spin_lock(&tlock);
	t = timer_lookup(timerid);
	if (t != NULL) {
		rb_del(&t->node, &utimers);
		list_del(&t->pnode);
		spin_lock(&t->lock);
		t->refc--;
	}
	spin_unlock(&tlock);

	if (t != NULL) {
		to_free = __timer_del(t);
		spin_unlock(&t->lock);

		if (to_free)
			kfree(t);
	}

	local_irq_restore(flags);

	return t ? 0 : -EINVAL;
}

static inline struct utimer *timer_cleanup_get(struct process *p)
{
	struct utimer *t = NULL;

	if (list_empty(&p->utimers))
		return NULL;

	spin_lock(&tlock);

	t = list_first_entry(&p->utimers, struct utimer, pnode);
	if (t != NULL) {
		rb_del(&t->node, &utimers);
		list_del(&t->pnode);
		spin_lock(&t->lock);
		t->refc--;
	}

	spin_unlock(&tlock);

	return t;
}

/*
 * callback for each process cleanup
 * to avoid resource leaking
 */
static void timer_cleanup(struct process *p)
{
	unsigned long flags = 0;
	struct utimer *t = NULL;
	bool to_free = false;

	local_irq_save(flags);

	while ((t = timer_cleanup_get(p)) != NULL) {
		DMSG("del %lx - pid %04d\n", t->id, p->id);
		to_free = __timer_del(t);
		spin_unlock(&t->lock);

		if (to_free)
			kfree(t);
	}

	local_irq_restore(flags);
}
DECLARE_CLEANUP_HIGH(timer_cleanup);

static inline intptr_t _timer_rbadd_cmp(
	const struct rb_node *n,
	const struct rb_node *ref)
{
	/* id is always positive number */
	return rb_entry_of(n, struct utimer, node)->id <
		rb_entry_of(ref, struct utimer, node)->id ? -1 : 1;
}

int timer_create(clockid_t clockid, struct sigevent *evp,
	timer_t *timerid)
{
	struct thread *curr = current;
	struct utimer *t = NULL;
	unsigned long flags = 0;
	bool invalidparam = false;

	if ((clockid != CLOCK_MONOTONIC) &&
		(clockid != CLOCK_REALTIME))
		return -EINVAL;

	t = kzalloc(sizeof(*t));
	if (t == NULL)
		return -ENOMEM;

	if (evp != NULL) {
		memcpy(&t->evp, evp, sizeof(*evp));

		if (t->evp.sigev_notify == SIGEV_THREAD) {
			if (t->evp.sigev_notify_attributes) {
				memcpy(&t->attr, evp->sigev_notify_attributes, sizeof(t->attr));

				if (t->attr.inheritsched == PTHREAD_INHERIT_SCHED) {
					t->attr.schedpolicy = curr->tuser->policy;
					t->attr.contentionscope = curr->tuser->scope;
					t->attr.schedparam.sched_priority = curr->tuser->priority;
				}
			}
		} else if (t->evp.sigev_notify == SIGEV_SIGNAL) {
			if (t->evp.sigev_signo < 1 || t->evp.sigev_signo >= NSIG)
				invalidparam = true;
		} else
			invalidparam = true;
	} else {
		t->evp.sigev_notify = SIGEV_SIGNAL;
		t->evp.sigev_signo = SIGALRM;
	}

	if (invalidparam) {
		kfree(t);
		return -EINVAL;
	}

	tevent_init(&t->tevent, timer_event, t);

	t->refc = 1;
	t->pid = curr->proc->id;
	t->clockid = clockid;
	INIT_WORK(&t->w, timer_worker);

	spin_lock_irqsave(&tlock, flags);
	t->id = timer_id_assign(curr->id);
	rb_add(&t->node, &utimers, _timer_rbadd_cmp);
	list_add_tail(&t->pnode, &curr->proc->utimers);
	spin_unlock_irqrestore(&tlock, flags);

	/*
	 *  Specifying evp as NULL is equivalent to specifying a pointer to
	 *  a sigevent structure in which sigev_notify is SIGEV_SIGNAL,
	 *  sigev_signo is SIGALRM, and sigev_value.sival_int is the timer ID.
	 */
	if (evp == NULL)
		t->evp.sigev_value = (union sigval)((void *)t->id);

	*timerid = t->id;

	return 0;
}

int timer_settime(timer_t timerid, int flags,
	const struct itimerspec *value,
	struct itimerspec *ovalue)
{
	int ret = -EINVAL;
	struct utimer *t = NULL;
	struct timespec diff;
	struct timespec curr;
	struct timespec tval;
	unsigned long slflags = 0;

	if (value == NULL)
		return -EINVAL;

	if (INVALID_TIMESPEC(&value->it_value) ||
		INVALID_TIMESPEC(&value->it_interval))
		return -EINVAL;

	t = timer_get_lock(timerid, &slflags);
	if (t == NULL)
		return -EINVAL;

	/*
	 * [EINVAL]
	 * The it_interval member of value is not zero and the timer
	 * was created with notification by creation of a new thread
	 * (sigev_notify was SIGEV_THREAD) and a fixed stack address
	 * has been set in the thread attribute
	 */
	if (timespecisset(&value->it_interval) &&
		((t->evp.sigev_notify == SIGEV_THREAD) &&
		t->attr.stackaddr))
		goto out;

	ret = clock_gettime(t->clockid, &curr);
	if (ret != 0)
		goto out;

	if (ovalue) {
		timespecsub(&t->ts.it_value, &curr, &diff);
		if (diff.tv_sec < 0)
			timespecclear(&ovalue->it_value);
		else
			ovalue->it_value = diff;

		ovalue->it_interval = t->ts.it_interval;
	}

	if (flags & TIMER_ABSTIME) {
		timespecsub(&value->it_value, &curr, &diff);
		if (diff.tv_sec >= 0) {
			tval = diff;
			t->ts.it_value = value->it_value;
		} else {
			t->ts.it_value = curr;
			tval = (struct timespec){0};
		}
	} else {
		timespecadd(&value->it_value, &curr, &diff);
		tval = value->it_value;
		t->ts.it_value = diff;
	}

	t->ts.it_interval = value->it_interval;

	if (t->refc == 1) {
		t->refc++;
		tevent_start(&t->tevent, &tval);
	} else {
		if (tevent_stop(&t->tevent))
			tevent_start(&t->tevent, &tval);
		else
			t->newval = tval;
	}

	ret = 0;

out:
	timer_put_lock(t, slflags);
	return ret;
}

int timer_gettime(timer_t timerid, struct itimerspec *value)
{
	int ret = -EINVAL;
	struct utimer *t = NULL;
	struct timespec diff;
	struct timespec curr;
	unsigned long slflags = 0;

	if (value == NULL)
		return -EINVAL;

	t = timer_get_lock(timerid, &slflags);
	if (t == NULL)
		return -EINVAL;

	clock_gettime(t->clockid, &curr);

	timespecsub(&t->ts.it_value, &curr, &diff);
	if (diff.tv_sec < 0)
		timespecclear(&value->it_value);
	else
		value->it_value = diff;

	value->it_interval = t->ts.it_interval;

	ret = 0;

	timer_put_lock(t, slflags);
	return ret;
}

int timer_getoverrun(timer_t timerid)
{
	int ret = -EINVAL;
	struct utimer *t = NULL;
	unsigned long slflags = 0;

	t = timer_get_lock(timerid, &slflags);
	if (t == NULL)
		return -EINVAL;

	ret = t->overrun;

	timer_put_lock(t, slflags);

	return ret;
}
