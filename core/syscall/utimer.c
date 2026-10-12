// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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
#include <atomic.h>
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
	/* bumped from the tevent ISR, consumed under t->lock -> must be atomic */
	struct atomic_num overrun;
	/* latched when a notification is accepted; what timer_getoverrun() reports */
	int overrun_last;
	pid_t pid;
	pid_t evplasttid;
	short refc;
	/* cleared on disarm/delete; an already queued work must not notify */
	bool armed;
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

/* SIGTIMER is generated as SIGALRM */
static inline int timer_signo(const struct utimer *t)
{
	int signo = t->evp.sigev_signo;

	return (signo == SIGTIMER) ? SIGALRM : signo;
}

/*
 * Drop a generated-but-undelivered notification on disarm/delete.  SIGTIMER
 * is exempt: its signal must survive the worker's auto-delete.
 */
static void timer_drop_pending(struct utimer *t)
{
	if (t->evp.sigev_signo == SIGTIMER)
		return;

	sigtimer_drop(t->pid, t->id);
}

static inline struct utimer *timer_lookup(timer_t id)
{
	pid_t pid = 0;
	struct utimer *t = timer_find(id);

	if (!t)
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
	} while (timer_find(id));

	return id;
}

static inline struct utimer *timer_get_lock(
	timer_t timerid, unsigned long *flags)
{
	struct utimer *t = NULL;
	unsigned long f = 0;

	spin_lock_irqsave(&tlock, f);

	t = timer_lookup(timerid);
	if (!t) {
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
	int ret = -1;
	bool to_free = false;
	struct process *proc = NULL;
	struct timespec tval;
	unsigned long flags = 0;
	struct utimer *t = container_of(w, struct utimer, w);
	timer_t id = t->id;
	bool evpsigtimer = false;

	spin_lock_irqsave(&t->lock, flags);

	/* disarmed while queued: t->pid may be freed/reused, don't look it up */
	if (!t->armed) {
		t->refc--;
		goto out;
	}

	proc = process_get(t->pid);
	if (!proc) {
		/* nothing will re-arm it now, so release this work's reference */
		t->refc--;
		goto out;
	}

	if (t->evp.sigev_notify == SIGEV_THREAD) {
		struct thread *lastthd = thread_get(t->evplasttid);

		if (!lastthd) {
			ret = pthread_kcreate(proc, &t->attr,
				(pthread_func_t)t->evp.sigev_notify_function,
				t->evp.sigev_value.sival_ptr);
			if (ret > 0) {
				t->evplasttid = ret;
				sched_ready(ret);
				/* a thread notification is accepted the moment it starts */
				t->overrun_last = atomic_read(&t->overrun);
				atomic_set(&t->overrun, 0);
			}
		} else {
			/* the previous callback is still running -> overrun */
			thread_put(lastthd);
			atomic_inc(&t->overrun);
		}
	} else {
		siginfo_t info = {timer_signo(t), SI_TIMER, t->evp.sigev_value};

		/*
		 * SIGTIMER (alarm()): deleted right after this notification, so
		 * the id is never reusable.
		 */
		evpsigtimer = (t->evp.sigev_signo == SIGTIMER);

		/* the core hands the id back at acceptance to latch si_overrun */
		info.si_timerid = t->id;
		ret = sigenqueue_info(t->pid, &info, false);
		if (ret != 0)
			atomic_inc(&t->overrun);
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
			unsigned long ovr = atomic_read(&t->overrun);

			usecs = max(ovr, 1ul) * max(usecs, 5000ul);
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

	/* an expiry that cannot queue a new notification is an overrun */
	if (!schedule_work(&t->w))
		atomic_inc(&t->overrun);
}

static bool __timer_del(struct utimer *t)
{
	timer_drop_pending(t);
	t->armed = false;
	timespecclear(&t->newval);
	timespecclear(&t->ts.it_interval);

	/* a queued work owns a reference; take it back only if it cannot run */
	if (tevent_stop(&t->tevent) || cancel_work(&t->w))
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
	if (t) {
		rb_del(&t->node, &utimers);
		list_del(&t->pnode);
		spin_lock(&t->lock);
		t->refc--;
	}
	spin_unlock(&tlock);

	if (t) {
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
	if (t) {
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
	DECLARE_DETACHED_PTHREAD_ATTR(dattr);

	if ((clockid != CLOCK_MONOTONIC) &&
		(clockid != CLOCK_REALTIME))
		return -EINVAL;

	t = kzalloc(sizeof(*t));
	if (!t)
		return -ENOMEM;

	if (evp) {
		memcpy(&t->evp, evp, sizeof(*evp));

		if (t->evp.sigev_notify == SIGEV_THREAD) {
			if (t->evp.sigev_notify_attributes)
				memcpy(&t->attr, evp->sigev_notify_attributes, sizeof(t->attr));
			else
				memcpy(&t->attr, &dattr, sizeof(t->attr));
			if (t->attr.inheritsched == PTHREAD_INHERIT_SCHED) {
				t->attr.schedpolicy = curr->tuser->policy;
				t->attr.contentionscope = curr->tuser->scope;
				t->attr.schedparam.sched_priority = curr->tuser->priority;
			}
			t->attr.detachstate = PTHREAD_CREATE_DETACHED;
		} else if (t->evp.sigev_notify == SIGEV_SIGNAL) {
			if (t->evp.sigev_signo < 1 || t->evp.sigev_signo >= NSIG)
				invalidparam = true;
		} else {
			invalidparam = true;
		}
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
	if (!evp)
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

	if (!value)
		return -EINVAL;

	if (INVALID_TIMESPEC(&value->it_value) ||
		INVALID_TIMESPEC(&value->it_interval))
		return -EINVAL;

	t = timer_get_lock(timerid, &slflags);
	if (!t)
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

	/* POSIX: a zero it_value disarms the timer, whatever it_interval says. */
	if (!timespecisset(&value->it_value)) {
		timer_drop_pending(t);
		t->armed = false;
		timespecclear(&t->ts.it_value);
		timespecclear(&t->ts.it_interval);
		timespecclear(&t->newval);
		if (tevent_stop(&t->tevent))
			t->refc--;
		ret = 0;
		goto out;
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
	t->armed = true;
	atomic_set(&t->overrun, 0);
	t->overrun_last = 0;

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

	if (!value)
		return -EINVAL;

	t = timer_get_lock(timerid, &slflags);
	if (!t)
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
	if (!t)
		return -EINVAL;

	/* POSIX caps the count at DELAYTIMER_MAX, which is INT_MAX here */
	ret = t->overrun_last;

	timer_put_lock(t, slflags);

	return ret;
}

/*
 * #info is the siginfo just dequeued, carrying our timer id in si_timerid
 * (0 = somebody else's signal).  POSIX: the overrun belongs to the
 * notification being accepted, not to the expiry.
 */
void sigtimer_accepted(siginfo_t *info)
{
	struct utimer *t = NULL;
	unsigned long flags = 0;

	if (!info || (info->si_timerid == 0))
		return;

	t = timer_get_lock(info->si_timerid, &flags);
	if (!t)
		return;

	t->overrun_last = atomic_read(&t->overrun);
	atomic_set(&t->overrun, 0);
	info->si_overrun = t->overrun_last;

	timer_put_lock(t, flags);
}
