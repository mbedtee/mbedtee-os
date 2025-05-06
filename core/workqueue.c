// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * work/worker queue
 */

#include <device.h>
#include <percpu.h>
#include <sched.h>
#include <list.h>
#include <timer.h>
#include <kthread.h>
#include <trace.h>
#include <delay.h>
#include <barrier.h>
#include <tasklet.h>
#include <tevent.h>
#include <kmalloc.h>
#include <workqueue.h>

#include <generated/autoconf.h>

static struct workqueue *system_wq;
static struct workqueue *system_highpri_wq;

/* Total 3s */
#define WORKER_IDLE_TIMEOUT (3000000UL)

#define WORKER_UNBIND_CPU (CONFIG_NR_CPUS)

#define WQ_MAX_WORKERS ((CONFIG_NR_CPUS > 2) ? (CONFIG_NR_CPUS) : 4)

#define WQ_ACTIVE  (1 << 0)
#define WQ_EXITING (1 << 1)

#define INVALID_WQ_CPU(x) ((unsigned int)(x) > WORKER_UNBIND_CPU)

#define workqueue_active(wq) \
	(atomic_read_x(&wq->state) == WQ_ACTIVE)

/*
 * worker struct is located at each thread's stack,
 * we use a magic number to check the worker was overflow.
 */
#define WORKER_MAGIC 0x2016051120180106LL
#define worker_overflow(wk) ((wk)->magic != WORKER_MAGIC)

struct worker {
	struct work *curr;
	struct workqueue *wq;/* at which workqueue */
	struct thread *thread;
	struct list_head node;
	struct list_head works;
	struct list_head flushers;
	struct spinlock lock;
	bool isidle; /* is idle or not */
	bool issystem; /* is system worker or not, like a rescuer, never quit */
	pid_t tid; /* thread id */
	int cpu; /* running at which CPU */
	int prio; /* worker's scheduler priority */
	long long magic;
};

struct flusher {
	struct work *w;
	struct list_head node;
	struct waitqueue wait_q;
};

static struct worker_list {
	struct spinlock lock;
	struct list_head workers;
} percpu_idle_worker[CONFIG_NR_CPUS + 1] = {0};

/* percpu system worker */
static struct worker *system_worker[CONFIG_NR_CPUS] = {NULL};
static struct worker *system_highpri_worker[CONFIG_NR_CPUS] = {NULL};

#define IS_SYSTEM_WQ(wq) ((wq) == system_wq || (wq) == system_highpri_wq)

static struct work *pick_next_work(
	struct worker *wk)
{
	struct work *w = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&wk->lock, flags);
	w = list_first_entry_or_null(&wk->works,
			struct work, node);
	wk->curr = w;
	if (w) {
		w->worker = (void *)(intptr_t)wk->tid;
		atomic_clear_zero(&w->busy);
		list_del(&w->node);
	}
	spin_unlock_irqrestore(&wk->lock, flags);
	return w;
}

static void __wakeup_flusher(struct work *w, struct worker *wk)
{
	struct flusher *flu = NULL, *n = NULL;

	list_for_each_entry_safe(flu, n, &wk->flushers, node) {
		if (flu->w == w) {
			list_del(&flu->node);
			wakeup(&flu->wait_q);
		}
	}
}

static void wakeup_flusher(struct work *w, struct worker *wk)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&wk->lock, flags);
	wk->curr = NULL; /* reject new flusher for current w */
	__wakeup_flusher(w, wk);
	spin_unlock_irqrestore(&wk->lock, flags);
}

static inline void enqueue_worker(
	struct workqueue *wq, struct worker *wk)
{
	list_add_tail(&wk->node, &wq->workers);
}

static inline void add_delayed_work(
	struct workqueue *wq, struct delayed_work *dw)
{
	assert(list_empty(&dw->node));

	list_add_tail(&dw->node, &wq->dws);
}

static inline void del_delayed_work(
	struct workqueue *wq, struct delayed_work *dw)
{
	list_del(&dw->node);

	/* wakeup_wq_flusher */
	if (list_empty(&wq->dws))
		wakeup(&wq->wait_q);
}

static void idle_worker(struct worker *wk)
{
	unsigned long flags = 0;
	struct workqueue *wq = wk->wq;
	struct worker_list *wl = &percpu_idle_worker[wk->cpu];

	spin_lock_irqsave(&wq->lock, flags);

	if (!wk->issystem && list_empty(&wk->works)) {
		list_del(&wk->node);

		spin_lock(&wl->lock);
		list_add_tail(&wk->node, &wl->workers);
		wk->isidle = true;
		spin_unlock(&wl->lock);

		/* wakeup_wq_flusher */
		if (list_empty(&wq->workers))
			wakeup(&wq->wait_q);
	}

	spin_unlock_irqrestore(&wq->lock, flags);
}

static inline void wakeup_worker(struct worker *wk)
{
	wakeup(&wk->thread->wait_q);
}

static struct worker *pick_idle_system_worker(
	int cpu, struct workqueue *wq)
{
	struct worker *wk = NULL, *ret = NULL;

	list_for_each_entry(wk, &wq->workers, node) {
		if (!list_empty(&wk->works))
			continue;

		if ((cpu == WORKER_UNBIND_CPU) || (wk->cpu == cpu)) {
			ret = wk;
			break;
		}
	}

	if (ret)
		list_move_tail(&ret->node, &wq->workers);

	return ret;
}

static struct worker *pick_busy_worker(
	int cpu, struct workqueue *wq)
{
	struct worker *wk = NULL, *ret = NULL;

	list_for_each_entry(wk, &wq->workers, node) {
		if ((cpu == WORKER_UNBIND_CPU) || (wk->cpu == cpu)) {
			ret = wk;
			break;
		}
	}

	if (ret)
		list_move_tail(&ret->node, &wq->workers);

	return ret;
}

static struct worker *pick_idle_worker(
	int cpu, struct workqueue *wq)
{
	struct worker *wk = NULL;
	struct worker_list *wl = NULL;
	int i = 0;

	if (IS_SYSTEM_WQ(wq)) {
		wk = pick_idle_system_worker(cpu, wq);
		if (wk)
			return wk;
	}

	for (i = WORKER_UNBIND_CPU; i >= 0; i--) {
		if ((cpu != WORKER_UNBIND_CPU) && (cpu != i))
			continue;

		wl = &percpu_idle_worker[i];
		spin_lock(&wl->lock);
		wk = list_last_entry_or_null(&wl->workers, struct worker, node);
		if (wk != NULL) {
			if (wq->prio != wk->prio) {
				struct sched_param p = {.sched_priority = wq->prio};

				sched_setparam(wk->tid, &p);
				wk->prio = wq->prio;
			}

			list_move_tail(&wk->node, &wq->workers);
			wk->isidle = false;

			if (wk->wq != wq) {
				strlcpy(wk->thread->name, wq->name,
					sizeof(wk->thread->name));
				wk->wq = wq;
			}
		}
		spin_unlock(&wl->lock);

		if (wk)
			break;
	}

	return wk;
}

static int destroy_worker(struct worker *wk)
{
	int ret = -EBUSY;
	struct worker_list *wl = &percpu_idle_worker[wk->cpu];
	unsigned long flags = 0;

	spin_lock_irqsave(&wl->lock, flags);

	if (!wk->isidle)
		goto out;

	list_del(&wk->node);

	ret = 0;

out:
	spin_unlock_irqrestore(&wl->lock, flags);
	return ret;
}

static inline int destroy_system_worker(struct worker *wk)
{
	int ret = -EBUSY;
	struct workqueue *wq = wk->wq;
	unsigned long flags = 0;

	spin_lock_irqsave(&wq->lock, flags);

	if (!INVALID_WQ_CPU(wk->cpu) || !list_empty(&wk->works))
		goto out;

	list_del(&wk->node);

	ret = 0;

out:
	spin_unlock_irqrestore(&wq->lock, flags);
	return ret;
}

static inline struct worker *worker_of(struct thread *t)
{
	return t->sched + sched_sizeof();
}

static void worker_thread(void *unused)
{
	struct work *w = NULL;
	struct worker *wk = worker_of(current);
	struct waitqueue *wait_q = &wk->thread->wait_q;

working:
	do {
		while ((w = pick_next_work(wk)) != NULL) {
			w->func(w);
			assert(!worker_overflow(wk));
			wakeup_flusher(w, wk);
		}

		if (INVALID_WQ_CPU(wk->cpu))
			break;

		idle_worker(wk);
	} while (wait_event_timeout(wait_q, (!list_empty(&wk->works) ||
		INVALID_WQ_CPU(wk->cpu)), WORKER_IDLE_TIMEOUT));

	if (wk->issystem) {
		if (!INVALID_WQ_CPU(wk->cpu))
			goto working;
		if (destroy_system_worker(wk) != 0)
			goto working;
	} else if (destroy_worker(wk) != 0)
		goto working;
}

static struct worker *create_worker(int cpu,
	struct workqueue *wq, bool issystem)
{
	pid_t tid = -1;
	int nrworkers = 0;
	struct thread *t = NULL;
	struct worker *wk = NULL;
	struct sched_param p = {.sched_priority = wq->prio};

	if (!issystem) {
		list_for_each_entry(wk, &wq->workers, node) {
			if (++nrworkers == WQ_MAX_WORKERS)
				return NULL;
		}
	}

	if (cpu == WORKER_UNBIND_CPU)
		tid = kthread_create(worker_thread, NULL, wq->name);
	else
		tid = kthread_create_on(worker_thread, NULL, cpu, wq->name);
	if (tid < 0)
		return NULL;

	t = thread_get(tid);
	if (t == NULL)
		return NULL;

	wk = worker_of(t);

	wk->thread = t;
	wk->cpu = cpu;
	wk->tid = tid;
	wk->magic = WORKER_MAGIC;
	spin_lock_init(&wk->lock);
	INIT_LIST_HEAD(&wk->works);
	INIT_LIST_HEAD(&wk->flushers);

	wk->wq = wq;
	wk->issystem = issystem;
	wk->isidle = false;
	enqueue_worker(wq, wk);

	sched_setscheduler(tid, wq->policy, &p);
	sched_ready(tid);

	thread_put(t);

	return wk;
}

static inline void insert_work(
	struct worker *wk, struct work *w)
{
	spin_lock(&wk->lock);
	assert(list_empty(&w->node));
	w->worker = wk;
	list_add_tail(&w->node, &wk->works);
	spin_unlock(&wk->lock);
}

static int enqueue_work(int cpu, struct workqueue *wq, struct work *w)
{
	struct worker *wk = NULL;

	wk = pick_idle_worker(cpu, wq);

	/*
	 * No more idle worker, going to create a new one
	 */
	if (!wk)
		wk = create_worker(cpu, wq, false);

	/*
	 * No more memory or worker pool is full,
	 * going to pick a busy worker
	 */
	if (!wk)
		wk = pick_busy_worker(cpu, wq);

	/*
	 * runs here, all busy! switch to the system_wq
	 */
	if (!wk)
		return -EBUSY;

	insert_work(wk, w);
	wakeup_worker(wk);

	return 0;
}

bool queue_work_on(int cpu, struct workqueue *wq, struct work *w)
{
	if (!w->func || INVALID_WQ_CPU(cpu))
		assert(false);

	bool ret = false;
	int stat = 0;
	struct worker *wk = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&wq->lock, flags);

	if (workqueue_active(wq) && atomic_compare_set(&w->busy, &stat, 1)) {
		if (enqueue_work(cpu, wq, w) != 0) {
			struct workqueue *newwq = NULL;

			/*
			 * runs here, all busy! switch to the system workqueue
			 */
			newwq = wq->prio <= SCHED_PRIO_DEFAULT ? system_wq : system_highpri_wq;

			spin_lock(&newwq->lock);
			wk = pick_idle_worker(cpu, newwq);
			if (!wk)
				wk = pick_busy_worker(cpu, newwq);
			/* ensure the wk, in case of the #cpu is not alive */
			if (!wk)
				wk = pick_idle_worker(WORKER_UNBIND_CPU, newwq);
			if (!wk)
				wk = pick_busy_worker(WORKER_UNBIND_CPU, newwq);

			insert_work(wk, w);
			wakeup_worker(wk);
			spin_unlock(&newwq->lock);
		}
		ret = true;
	}

	spin_unlock_irqrestore(&wq->lock, flags);
	return ret;
}

bool queue_work(struct workqueue *wq, struct work *w)
{
	return queue_work_on(WORKER_UNBIND_CPU, wq, w);
}

static void enqueue_delayed_work(
	struct workqueue *wq, struct delayed_work *dw)
{
	int cpu = dw->cpu;
	struct worker *wk = NULL;

	/* already been cancelled ? */
	if (!list_empty(&dw->node)) {
		del_delayed_work(wq, dw);

		if (enqueue_work(cpu, wq, &dw->w) != 0) {
			/*
			 * runs here, all busy! switch to the system workqueue
			 */
			wq = wq->prio <= SCHED_PRIO_DEFAULT ? system_wq : system_highpri_wq;

			spin_lock(&wq->lock);
			wk = pick_idle_worker(cpu, wq);
			if (!wk)
				wk = pick_busy_worker(cpu, wq);
			/* ensure the wk, in case of the #cpu is not alive */
			if (!wk)
				wk = pick_idle_worker(WORKER_UNBIND_CPU, wq);
			if (!wk)
				wk = pick_busy_worker(WORKER_UNBIND_CPU, wq);

			dw->wq = wq;
			insert_work(wk, &dw->w);
			wakeup_worker(wk);
			spin_unlock(&wq->lock);
		}
	}
}

static void delayed_work_event(struct tevent *e)
{
	struct delayed_work *dw = container_of(e, struct delayed_work, timer);
	struct workqueue *wq = dw->wq;
	unsigned long flags = 0;

	spin_lock_irqsave(&wq->lock, flags);
	if (workqueue_active(wq))
		enqueue_delayed_work(wq, dw);
	spin_unlock_irqrestore(&wq->lock, flags);
}

bool queue_delayed_work_on(int cpu, struct workqueue *wq,
	struct delayed_work *dw, useconds_t usecs)
{
	bool ret = false;
	int stat = 0;
	struct timespec time;
	struct work *w = &dw->w;
	unsigned long flags = 0;

	if (!w->func || INVALID_WQ_CPU(cpu))
		assert(false);

	spin_lock_irqsave(&wq->lock, flags);

	if (workqueue_active(wq) && atomic_compare_set(&w->busy, &stat, 1)) {
		add_delayed_work(wq, dw);
		dw->wq = wq;
		dw->cpu = cpu;

		if (usecs != 0) {
			usecs_to_time(usecs, &time);
			tevent_init(&dw->timer, delayed_work_event, dw);
			tevent_start(&dw->timer, &time);
		} else {
			enqueue_delayed_work(wq, dw);
		}
		ret = true;
	}
	spin_unlock_irqrestore(&wq->lock, flags);

	return ret;
}

bool queue_delayed_work(struct workqueue *wq,
	struct delayed_work *dw, useconds_t usecs)
{
	return queue_delayed_work_on(WORKER_UNBIND_CPU, wq, dw, usecs);
}

/*
 * return true if this function modified the timer,
 * or started a new delayed_work
 * otherwise return false (e.g. already been queued).
 */
bool mod_delayed_work_on(int cpu, struct workqueue *wq,
	struct delayed_work *dw, useconds_t usecs)
{
	bool ret = false;
	struct timespec time;
	unsigned long flags = 0;

	local_irq_save(flags);

	if (wq == NULL)
		wq = system_wq;

again:
	if (workqueue_active(wq)) {
		if (tevent_stop(&dw->timer)) {
			if (usecs == 0) {
				delayed_work_event(&dw->timer);
			} else {
				usecs_to_time(usecs, &time);
				tevent_start(&dw->timer, &time);
			}
			ret = true;
		} else {
			if (list_empty(&dw->w.node)) {
				if (!queue_delayed_work_on(cpu, wq, dw, usecs))
					goto again;

				ret = true;
			}
		}
	}

	local_irq_restore(flags);
	return ret;
}

/*
 * return true if this function modified the timer,
 * or started a new delayed_work
 * otherwise return false (e.g. already been queued).
 */
bool mod_delayed_work(struct workqueue *wq,
	struct delayed_work *dw, useconds_t usecs)
{
	return mod_delayed_work_on(WORKER_UNBIND_CPU, wq, dw, usecs);
}

/* wait for the work finish or cancelled */
static void wait_work_finish(struct work *w, struct worker *wk)
{
	struct flusher flu = {.w = w};

	waitqueue_init(&flu.wait_q);
	list_add_tail(&flu.node, &wk->flushers);
	spin_unlock(&wk->lock);
	wait(&flu.wait_q);
}

static bool check_wait_work_finish(struct work *w)
{
	bool ret = false;
	struct worker *wk = w->worker;
	pid_t tid = (intptr_t)wk;
	struct thread *t = thread_get(tid);

	if (t != NULL) {
		wk = worker_of(t);
		if (!worker_overflow(wk) && (wk->tid == tid) &&
			(wk->thread == t) && (wk->curr == w)) {
			spin_lock(&wk->lock);
			if (wk->curr == w) {
				wait_work_finish(w, wk);
				ret = true;
			} else {
				spin_unlock(&wk->lock);
			}
		}
		thread_put(t);
	}

	return ret;
}

static bool __flush_work(struct work *w, bool isdelaywk)
{
	bool ret = false;
	struct worker *wk = NULL;
	unsigned long flags = 0;
	struct delayed_work *dw = NULL;

	local_irq_save(flags);

	if (isdelaywk)
		dw = container_of(w, struct delayed_work, w);

again:
	if (isdelaywk && tevent_stop(&dw->timer))
		delayed_work_event(&dw->timer);

	/* make sure w->worker is visible */
	smp_mb();
	wk = w->worker;
	if (!IS_ERR_PTR(wk)) {
		spin_lock(&wk->lock);
		if (wk != w->worker) {
			spin_unlock(&wk->lock);
			goto again;
		}

		wait_work_finish(w, wk);
		ret = true;
	} else {
		ret = check_wait_work_finish(w);
	}

	local_irq_restore(flags);
	return ret;
}

bool flush_work(struct work *w)
{
	return __flush_work(w, false);
}

/*
 * return true if this function cancelled this delayed_work,
 * otherwise return false (e.g. work already been picked or still be handling).
 */
bool cancel_delayed_work(struct delayed_work *dw)
{
	bool ret = false;
	unsigned long flags = 0;
	struct work *w = &dw->w;
	struct worker *wk = NULL;
	struct workqueue *wq = NULL;

	local_irq_save(flags);

again:
	/* make sure updates to #dw/#wk are visible */
	smp_mb();
	if (tevent_stop(&dw->timer)) {
		wq = dw->wq;
		spin_lock(&wq->lock);
		del_delayed_work(wq, dw);
		spin_unlock(&wq->lock);
		ret = true;
	} else {
		if (!list_empty(&dw->node)) {
			wq = dw->wq;
			spin_lock(&wq->lock);
			if (wq != dw->wq || list_empty(&dw->node)) {
				spin_unlock(&wq->lock);
				goto again;
			}
			del_delayed_work(wq, dw);
			spin_unlock(&wq->lock);
			ret = true;
		} else {
			wk = w->worker;
			if (!IS_ERR_PTR(wk)) {
				spin_lock(&wk->lock);
				if (wk != w->worker) {
					spin_unlock(&wk->lock);
					goto again;
				}

				list_del(&w->node);
				w->worker = NULL;
				ret = true;

				__wakeup_flusher(w, wk);
				spin_unlock(&wk->lock);
			}
		}
	}

	/* cancelled by this func */
	if (ret == true)
		atomic_clear_zero(&w->busy);

	local_irq_restore(flags);
	return ret;
}

bool cancel_delayed_work_sync(struct delayed_work *dw)
{
	int stat = 0;
	bool ret = false;
	unsigned long flags = 0;
	struct work *w = &dw->w;
	struct worker *wk = NULL;
	struct workqueue *wq = NULL;

	local_irq_save(flags);

again:
	/* make sure updates to #dw/#wk are visible */
	smp_mb();
	if (tevent_stop(&dw->timer)) {
		wq = dw->wq;
		spin_lock(&wq->lock);
		del_delayed_work(wq, dw);
		atomic_clear_zero(&w->busy);
		spin_unlock(&wq->lock);
		ret = true;
	} else {
		if (atomic_compare_set(&w->busy, &stat, 1)) {
			ret = check_wait_work_finish(w);
			atomic_clear_zero(&w->busy);
		} else if (!list_empty(&dw->node)) {
			wq = dw->wq;
			spin_lock(&wq->lock);
			if (wq != dw->wq || list_empty(&dw->node)) {
				spin_unlock(&wq->lock);
				goto again;
			}
			del_delayed_work(wq, dw);
			atomic_clear_zero(&w->busy);
			spin_unlock(&wq->lock);
			ret = true;
		} else {
			wk = w->worker;
			if (!IS_ERR_PTR(wk)) {
				spin_lock(&wk->lock);
				if (wk != w->worker) {
					spin_unlock(&wk->lock);
					goto again;
				}

				list_del(&w->node);
				w->worker = NULL;
				ret = true;
				atomic_clear_zero(&w->busy);
				__wakeup_flusher(w, wk);
				spin_unlock(&wk->lock);
			} else {
				goto again;
			}
		}
	}

	local_irq_restore(flags);
	return ret;
}

/*
 * stop the pending timer, queue/flush the work directly
 */
bool flush_delayed_work(struct delayed_work *dw)
{
	return __flush_work(&dw->w, true);
}

/*
 * return true if this function cancelled this work,
 * otherwise return false (e.g. work already been picked or still be handling).
 */
bool cancel_work(struct work *w)
{
	bool ret = false;
	unsigned long flags = 0;
	struct worker *wk = NULL;

	local_irq_save(flags);

again:
	/* make sure w->worker is visible */
	smp_mb();
	wk = w->worker;
	if (!IS_ERR_PTR(wk)) {
		spin_lock(&wk->lock);
		if (wk != w->worker) {
			spin_unlock(&wk->lock);
			goto again;
		}

		list_del(&w->node);
		w->worker = NULL;
		ret = true;
		atomic_clear_zero(&w->busy);

		__wakeup_flusher(w, wk);
		spin_unlock(&wk->lock);
	}

	local_irq_restore(flags);
	return ret;
}

bool cancel_work_sync(struct work *w)
{
	int stat = 0;
	bool ret = false;
	unsigned long flags = 0;
	struct worker *wk = NULL;

	local_irq_save(flags);

again:
	/* block others, block the re-arm */
	if (atomic_compare_set(&w->busy, &stat, 1)) {
		ret = check_wait_work_finish(w);
		atomic_clear_zero(&w->busy);
	} else {
		wk = w->worker;
		if (!IS_ERR_PTR(wk)) {
			spin_lock(&wk->lock);
			if (wk != w->worker) {
				spin_unlock(&wk->lock);
				goto again;
			}

			list_del(&w->node);
			/* resume the stat */
			w->worker = NULL;
			atomic_clear_zero(&w->busy);

			__wakeup_flusher(w, wk);
			spin_unlock(&wk->lock);
			ret = true;
		} else
			goto again;
	}

	local_irq_restore(flags);
	return ret;
}

bool schedule_work(struct work *w)
{
	return queue_work_on(WORKER_UNBIND_CPU, system_wq, w);
}

bool schedule_highpri_work(struct work *w)
{
	return queue_work_on(WORKER_UNBIND_CPU, system_highpri_wq, w);
}

bool schedule_delayed_work(struct delayed_work *dw,
	useconds_t usecs)
{
	return queue_delayed_work_on(WORKER_UNBIND_CPU, system_wq, dw, usecs);
}

bool schedule_work_on(int cpu, struct work *w)
{
	return queue_work_on(cpu, system_wq, w);
}

bool schedule_highpri_work_on(int cpu, struct work *w)
{
	return queue_work_on(cpu, system_highpri_wq, w);
}

bool schedule_delayed_work_on(int cpu,
	struct delayed_work *dw, useconds_t usecs)
{
	return queue_delayed_work_on(cpu, system_wq, dw, usecs);
}

static bool __schedule_work_on_noalloc(int cpu,
	struct work *w, struct workqueue *wq)
{
	bool ret = false;
	int stat = 0;
	struct worker *wk = NULL;
	unsigned long flags = 0;

	if (!w->func || INVALID_WQ_CPU(cpu))
		assert(false);

	spin_lock_irqsave(&wq->lock, flags);

	if (atomic_compare_set(&w->busy, &stat, 1)) {
		wk = pick_idle_worker(cpu, wq);
		if (!wk)
			wk = pick_busy_worker(cpu, wq);

		/* ensure the wk, in case of the #cpu is not alive */
		if (!wk)
			wk = pick_idle_worker(WORKER_UNBIND_CPU, wq);
		if (!wk)
			wk = pick_busy_worker(WORKER_UNBIND_CPU, wq);

		if ((cpu != WORKER_UNBIND_CPU) && (wk->cpu != cpu))
			WMSG("%s -> cpu %d isn't on demand of %d\n", wq->name, wk->cpu, cpu);

		insert_work(wk, w);
		wakeup_worker(wk);
		ret = true;
	}

	spin_unlock_irqrestore(&wq->lock, flags);

	return ret;
}

bool __schedule_work_on(int cpu, struct work *w)
{
	return __schedule_work_on_noalloc(cpu, w, system_wq);
}

bool __schedule_work(struct work *w)
{
	return __schedule_work_on_noalloc(WORKER_UNBIND_CPU, w, system_wq);
}

bool __schedule_highpri_work_on(int cpu, struct work *w)
{
	return __schedule_work_on_noalloc(cpu, w, system_highpri_wq);
}

static void __enqueue_delayed_work_noalloc(struct workqueue *wq,
	struct delayed_work *dw)
{
	int cpu = dw->cpu;
	struct worker *wk = NULL;

	/* already been cancelled ? */
	if (!list_empty(&dw->node)) {
		del_delayed_work(wq, dw);

		wk = pick_idle_worker(cpu, wq);
		if (!wk)
			wk = pick_busy_worker(cpu, wq);
		/* ensure the wk, in case of the #cpu is not alive */
		if (!wk)
			wk = pick_idle_worker(WORKER_UNBIND_CPU, wq);
		if (!wk)
			wk = pick_busy_worker(WORKER_UNBIND_CPU, wq);

		if ((cpu != WORKER_UNBIND_CPU) && (wk->cpu != cpu))
			WMSG("%s -> cpu %d isn't on demand of %d\n", wq->name, wk->cpu, cpu);

		insert_work(wk, &dw->w);
		wakeup_worker(wk);
	}
}

static void __delayed_work_event_noalloc(struct tevent *e)
{
	unsigned long flags = 0;
	struct delayed_work *dw = container_of(e, struct delayed_work, timer);
	struct workqueue *wq = dw->wq;

	spin_lock_irqsave(&wq->lock, flags);

	__enqueue_delayed_work_noalloc(wq, dw);

	spin_unlock_irqrestore(&wq->lock, flags);
}

static bool __schedule_delayed_work_noalloc_on(
	int cpu, struct delayed_work *dw,
	useconds_t usecs, struct workqueue *wq)
{
	bool ret = false;
	int stat = 0;
	struct timespec time;
	struct work *w = &dw->w;
	unsigned long flags = 0;

	if (!w->func || INVALID_WQ_CPU(cpu))
		assert(false);

	spin_lock_irqsave(&wq->lock, flags);

	if (atomic_compare_set(&w->busy, &stat, 1)) {
		add_delayed_work(wq, dw);
		dw->wq = wq;
		dw->cpu = cpu;

		if (usecs != 0) {
			usecs_to_time(usecs, &time);
			tevent_init(&dw->timer, __delayed_work_event_noalloc, dw);
			tevent_start(&dw->timer, &time);
		} else {
			__enqueue_delayed_work_noalloc(wq, dw);
		}

		ret = true;
	}
	spin_unlock_irqrestore(&wq->lock, flags);

	return ret;
}

bool __schedule_delayed_work_on(
	int cpu, struct delayed_work *dw, useconds_t usecs)
{
	return __schedule_delayed_work_noalloc_on(cpu, dw, usecs, system_wq);
}

bool __schedule_delayed_work(
	struct delayed_work *dw, useconds_t usecs)
{
	return __schedule_delayed_work_noalloc_on(WORKER_UNBIND_CPU, dw, usecs, system_wq);
}

static bool __mod_delayed_work_noalloc_on(int cpu,
	struct delayed_work *dw, useconds_t usecs, struct workqueue *wq)
{
	bool ret = false;
	struct timespec time;
	unsigned long flags = 0;

	local_irq_save(flags);

again:
	if (tevent_stop(&dw->timer)) {
		if (usecs == 0) {
			__delayed_work_event_noalloc(&dw->timer);
		} else {
			usecs_to_time(usecs, &time);
			tevent_start(&dw->timer, &time);
		}
		ret = true;
	} else {
		if (list_empty(&dw->w.node)) {
			if (!__schedule_delayed_work_noalloc_on(cpu, dw, usecs, wq))
				goto again;

			ret = true;
		}
	}

	local_irq_restore(flags);
	return ret;
}

bool __mod_delayed_work(struct delayed_work *dw, useconds_t usecs)
{
	return __mod_delayed_work_noalloc_on(WORKER_UNBIND_CPU, dw, usecs, system_wq);
}
bool __mod_delayed_work_on(int cpu, struct delayed_work *dw, useconds_t usecs)
{
	return __mod_delayed_work_noalloc_on(cpu, dw, usecs, system_wq);
}

struct workqueue *create_workqueue(const char *fmt, ...)
{
	va_list args;
	struct workqueue *wq = NULL;

	if (fmt == NULL)
		return NULL;

	wq = kzalloc(sizeof(struct workqueue));
	if (!wq)
		return NULL;

	va_start(args, fmt);
	vsnprintf(wq->name, sizeof(wq->name), fmt, args);
	va_end(args);

	wq->prio = SCHED_PRIO_DEFAULT;
	wq->policy = SCHED_RR;
	wq->state = WQ_ACTIVE;
	spin_lock_init(&wq->lock);
	waitqueue_init(&wq->wait_q);
	INIT_LIST_HEAD(&wq->dws);
	INIT_LIST_HEAD(&wq->workers);

	return wq;
}

void workqueue_setscheduler(
	struct workqueue *wq,
	int policy, int prio)
{
	unsigned long flags = 0;
	struct worker *wk = NULL;
	struct sched_param p = {.sched_priority = prio};

	spin_lock_irqsave(&wq->lock, flags);
	if (workqueue_active(wq)) {
		wq->policy = policy;
		wq->prio = prio;
		list_for_each_entry(wk, &wq->workers, node)
			sched_setscheduler(wk->tid, policy, &p);
	}
	spin_unlock_irqrestore(&wq->lock, flags);
}

void flush_workqueue(struct workqueue *wq)
{
	if (wq) {
		wait_event(&wq->wait_q,
			list_empty(&wq->dws) &&
			list_empty(&wq->workers));
	}
}

void destroy_workqueue(struct workqueue *wq)
{
	if (wq) {
		struct worker *wk = NULL;
		struct delayed_work *dw = NULL;
		unsigned long flags = 0;

		spin_lock_irqsave(&wq->lock, flags);

		wq->state = WQ_EXITING;

		do {
			dw = list_first_entry_or_null(&wq->dws,
				struct delayed_work, node);
			spin_unlock_irqrestore(&wq->lock, flags);
			cancel_delayed_work(dw);
			spin_lock_irqsave(&wq->lock, flags);
		} while (dw);

		list_for_each_entry(wk, &wq->workers, node)
			wakeup_worker(wk);
		spin_unlock_irqrestore(&wq->lock, flags);

		flush_workqueue(wq);

		spin_lock_irqsave(&wq->lock, flags);
		spin_unlock_irqrestore(&wq->lock, flags);

		kfree(wq);
	}
}

static void system_worker_init(void)
{
	int cpu = 0;
	unsigned long flags = 0;
	struct worker *wk = NULL, *hwk = NULL;

	local_irq_save(flags);

	cpu = percpu_id();

	wk = create_worker(cpu, system_wq, true);

	hwk = create_worker(cpu, system_highpri_wq, true);

	system_worker[cpu] = wk;
	system_highpri_worker[cpu] = hwk;

	local_irq_restore(flags);

	if (!wk || !hwk) {
		EMSG("create_system_worker failed\n");
		cpu_set_error();
	}
}

static void system_worker_down(void)
{
	int cpu = percpu_id();
	struct worker *wk = system_worker[cpu];
	struct worker *hwk = system_highpri_worker[cpu];
	unsigned long flags = 0;

	/* async quit the binded system worker */

	if (wk) {
		system_worker[cpu] = NULL;
		spin_lock_irqsave(&system_wq->lock, flags);
		wk->cpu = -1;
		list_del(&wk->node);
		wakeup_worker(wk);
		spin_unlock_irqrestore(&system_wq->lock, flags);
	}

	if (hwk) {
		system_highpri_worker[cpu] = NULL;
		spin_lock_irqsave(&system_highpri_wq->lock, flags);
		hwk->cpu = -1;
		list_del(&hwk->node);
		wakeup_worker(hwk);
		spin_unlock_irqrestore(&system_highpri_wq->lock, flags);
	}
}

void workqueue_init(void)
{
	if (!system_wq) {
		int i = 0;

		system_wq = create_workqueue("kworker");
		system_highpri_wq = create_workqueue("kworker-H");

		assert(system_wq && system_highpri_wq);

		workqueue_setscheduler(system_highpri_wq,
			SCHED_RR, SCHED_HIGHPRIO_DEFAULT);

		for (i = WORKER_UNBIND_CPU; i >= 0; i--) {
			spin_lock_init(&percpu_idle_worker[i].lock);
			INIT_LIST_HEAD(&percpu_idle_worker[i].workers);
		}
	}

	/* create system workers(1 normal + 1 highpri) for each CPU */
	system_worker_init();
}

/*
 * For CPU Hot-Plug
 * Force quit the per-cpu system worker
 */
void worker_down(void)
{
	system_worker_down();
}
