// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * scheduler implementation
 */

#include <cpu.h>
#include <str.h>
#include <string.h>
#include <sleep.h>
#include <trace.h>
#include <percpu.h>
#include <timer.h>
#include <tevent.h>
#include <kthread.h>
#include <vmalloc.h>
#include <errno.h>
#include <sched.h>
#include <backtrace.h>
#include <interrupt.h>
#include <tasklet.h>
#include <device.h>

#include <__pthread.h>

#include "sched_priv.h"
#include "sched_record.h"
#include "sched_list.h"
#include "sched_timer.h"

struct sched_gd __sched_gd
	__section(".bss") = {0};

struct sched_priv __sched_priv[CONFIG_NR_CPUS]
	__section(".bss")
	__aligned(64) = {NULL};

/* Background scheduler tick interval */
#define SCHED_INTERVAL_USEC (8192UL) /* Microseconds */
#define SCHED_INTERVAL_SHIFT_MAX (4U) /* DIV factor*/

static int sched_alloc_id(void)
{
	pid_t id = -1;

	id = ida_alloc(&sched_gd()->sched_ida);
	if (id <= 0) {
		EMSG("out of sched id\n");
		return -EBUSY;
	}

	return id;
}

void sched_free_id(pid_t id)
{
	if (SCHED_ID_VALID(id))
		ida_free(&sched_gd()->sched_ida, id);
}

/*
 * uninstall sched structure
 */
static void __sched_uninstall(struct sched *s)
{
	struct thread *t = s->thread;

	if (!list_empty(&s->ready_node))
		WMSG("%s - %s\n", t->name, sched_state(s->state));

	/* reject new joiners */
	t->join_q.condi = -(INT_MAX >> 1);

	atomic_dec(&t->proc->alive);

	__sched_del(s);
}

static void _sched_uninstall(struct sched *s)
{
	struct sched_priv *sp = s->sp;

	spin_lock(&sp->lock);

	__sched_uninstall(s);

	spin_unlock(&sp->lock);
}

/*
 * uninstall sched structure, only for the
 * error handling @ thread creation
 */
void sched_uninstall(void *sched_t)
{
	if (sched_t) {
		struct sched *s = sched_t;
		struct sched_gd *gd = sched_gd();
		unsigned long flags = 0;

		spin_lock_irqsave(&gd->lock, flags);

		_sched_uninstall(s);

		s->thread->sched = NULL;

		spin_unlock_irqrestore(&gd->lock, flags);

		sched_free_id(s->id);
	}
}

/* trigger the next timer event for scheduling */
static void sched_rotate(struct sched_priv *sp,
	unsigned long usecs)
{
	struct timespec time = {0};
	unsigned int shift = 0;

	/*
	 * upshift the scheduler based on the ready_num,
	 * to ensure the TEE responsiveness
	 */
	shift = min((typeof(sp->ready_num))SCHED_INTERVAL_SHIFT_MAX,
				sp->ready_num);
	/*
	 * The 'usecs' always less than 1000000
	 */
	time.tv_nsec = usecs << (10 - shift);

	tevent_renew(&sp->tevent, &time);
}

static void sched_update_state(struct sched_priv *sp,
	struct sched *curr, struct sched *next)
{
	sp->curr = next;

	/* update new round-robin priority ceiling */
	if (next->policy != SCHED_OTHER)
		sp->rrprio = next->priority;

	next->state = SCHED_RUNNING;

	if (curr && (curr->state == SCHED_RUNNING))
		curr->state = SCHED_READY;
}

static int __sched_switch_affinity_cpu(
	struct sched_priv *ori, struct sched *s)
{
	struct sched_priv *dst = NULL;
	struct sched_gd *gd = sched_gd();

	if (cpu_affinity_isset(s->affinity, ori->pc->id))
		return 0;

	if (s == ori->curr)
		return 0;

	dst = __sched_pick_affinity_cpu(s, gd);
	if (dst == NULL)
		return -EINVAL;

	__sched_sp_del(ori, s);

	spin_lock(&dst->lock);
	__sched_sp_add(dst, s);
	if (!list_empty(&s->ready_node)) {
		sched_list_del(ori, s);
		sched_idlecpu_inc(ori, gd);
		sched_list_add(dst, s);
		sched_idlecpu_dec(dst);
	}
	spin_unlock(&dst->lock);

	return 0;
}

static void sched_switch_affinity_cpu(pid_t id)
{
	struct sched *s = NULL;
	struct sched_priv *sp = NULL;
	unsigned long flags = 0;

	s = sched_get_lock(id, &flags);
	if (s) {
		sp = s->sp;
		spin_lock(&sp->lock);
		__sched_switch_affinity_cpu(sp, s);
		spin_unlock(&sp->lock);
	}
	sched_put_lock(s, flags);
}

static void sched_enqueue_on(struct sched *s,
	struct sched_priv *dst)
{
	struct sched_priv *ori = s->sp;

	spin_lock(&ori->lock);

	sched_timer_stop(s);

	if (!list_empty(&s->ready_node)) {
		spin_unlock(&ori->lock);
		return;
	}

	if (s != ori->curr) {
		__sched_sp_del(ori, s);
		spin_unlock(&ori->lock);

		spin_lock(&dst->lock);
		__sched_sp_add(dst, s);
		sched_list_add(dst, s);
		sched_idlecpu_dec(dst);
		s->state = SCHED_READY;
		spin_unlock(&dst->lock);
	} else {
		s->state = SCHED_RUNNING;
		sched_list_add(ori, s);
		sched_idlecpu_dec(ori);
		spin_unlock(&ori->lock);
	}
}

static void __sched_enqueue(struct sched *s)
{
	struct sched_priv *sp = s->sp;

	sched_timer_stop(s);

	if (list_empty(&s->ready_node)) {
		s->state = (s != sp->curr) ? SCHED_READY : SCHED_RUNNING;
		sched_list_add(sp, s);
		sched_idlecpu_dec(sp);
	}
}

static void sched_enqueue(struct sched *s)
{
	struct sched_priv *sp = s->sp;

	spin_lock(&sp->lock);

	__sched_enqueue(s);

	spin_unlock(&sp->lock);
}

/*
 * dequeue a sched entity from its CPU's scheduler list
 */
void sched_dequeue(struct sched *s, int state)
{
	struct sched_gd *gd = sched_gd();
	struct sched_priv *sp = NULL;

	/*
	 * Global lock to ensure the s->sp is atomic
	 */
	spin_lock_irq(&gd->lock);

	sp = s->sp;

	spin_lock(&sp->lock);
	sched_timer_stop(s);
	if (!list_empty(&s->ready_node)) {
		sched_idlecpu_inc(sp, gd);
		sched_list_del(sp, s);
	}

	/* make sure it will never be found again by sched_get() */
	if (state == SCHED_EXIT) {
		/*
		 * the sched-entity is exiting, so the thread is dead
		 */
		if (s->state != SCHED_EXIT)
			__sched_uninstall(s);
	}

	s->state = state;

	spin_unlock(&sp->lock);

	spin_unlock(&gd->lock);

	/*
	 * due to the global FIQ is enabled when executing
	 * the software generated interrupts (SVC syscall),
	 * so the local_irq_enable function should not be called on
	 * this critical ctx-swap duration, otherwise the FIQ may
	 * occur, and the FIQ routine may execute _sched_exec(),
	 * then this swapped ctx will be disturbed.
	 *
	 * local_irq_restore(flags);
	 */
}

/*
 * dequeue a sched entity from its CPU's scheduler list
 *
 * compare to sched_queue(), this function sets
 * a wakeup timer, this timer event wakes up this
 * sched entity after the timeout elapsed
 */
void sched_timed_dequeue(struct sched *s,
	int state, struct timespec *time)
{
	struct sched_gd *gd = sched_gd();
	struct sched_priv *sp = NULL;

	/*
	 * Global lock to ensure the s->sp is atomic
	 */
	spin_lock_irq(&gd->lock);

	sp = s->sp;

	spin_lock(&sp->lock);

	if (!list_empty(&s->ready_node)) {
		sched_idlecpu_inc(sp, gd);
		sched_list_del(sp, s);
	}

	sched_timer_start(s, time);
	s->state = state;

	spin_unlock(&sp->lock);

	spin_unlock(&gd->lock);

	/*
	 * due to the global FIQ is enabled when executing
	 * the software generated interrupts (SVC syscall),
	 * so the local_irq_enable function should not be called on
	 * this critical ctx-swap duration, otherwise the FIQ may
	 * occur, and the FIQ routine may execute _sched_exec(),
	 * then this swapped ctx will be disturbed.
	 *
	 * local_irq_restore(flags);
	 */
}

void __sched_exec(struct sched_priv *sp,
	struct thread_ctx *regs)
{
	struct sched *curr = NULL;
	struct sched *next = NULL;
	pid_t affinitylost = 0;

	if (regs == NULL)
		return;

	spin_lock(&sp->lock);

	curr = sp->curr;

	sched_record_curr(curr);

	sched_update_curr(sp, curr);

	if (sp->ready_num == 0)
		next = sched_pick_global(sp);

	if (!next)
		next = sched_pick_next(sp);

	if (curr != next) {
		sp->archops->switch_ctx(curr, next, regs);

		if (curr && !cpu_affinity_isset(
			curr->affinity, sp->pc->id))
			affinitylost = curr->id;

		sched_update_state(sp, curr, next);
		sched_record_next(next);

		if (sched_sigcheck(curr))
			__sched_enqueue(curr);
	}

	sched_record_runtime(sp);

	spin_unlock(&sp->lock);

	if (affinitylost)
		sched_switch_affinity_cpu(affinitylost);
}

void __sched_exec_specified(
	struct sched_priv *sp, struct sched *next,
	struct thread_ctx *regs)
{
	struct sched *curr = NULL;

	spin_lock(&sp->lock);

	curr = sp->curr;

	sched_record_curr(curr);

	sched_update_curr(sp, curr);

	if (curr != next) {
		sp->archops->switch_ctx(curr, next, regs);
		sched_update_state(sp, curr, next);
		sched_record_next(next);
	}

	sched_record_runtime(sp);

	if (sched_sigcheck(curr))
		__sched_enqueue(curr);

	spin_unlock(&sp->lock);
}

void sched_notify_waiter(
	struct sched_priv *sp, struct sched *curr,
	struct thread_ctx *regs, long lastwords)
{
	struct thread *t = curr->thread;

	sp->pc->int_ctx = regs;
	wakeup_notify(&t->join_q, lastwords);
	sp->pc->int_ctx = NULL;

	if (sp->curr == curr)
		__sched_exec(sp, regs);
}

/*
 * running with IRQ stack
 *
 * pick next sched entity to run
 */
void *sched_exec(struct thread_ctx *regs)
{
	struct sched_priv *sp = sched_priv();
	struct sched *s = sp->curr;
	struct thread *t = NULL;
	int s_stat = 0;

	if (s && (s->s_stat != 0)) {
		s_stat = s->s_stat;
		s->s_stat = 0;
		t = s->thread;
		if (s_stat == SCHED_SUSPENDING) {
			sched_dequeue(s, SCHED_SUSPEND);
			sched_notify_waiter(sp, s, regs, t->join_q.notification);
			mutex_unlock(&t->mlock);
		} else if (s_stat == SCHED_EXITING) {
			sched_dequeue(s, SCHED_EXIT);
			sched_notify_waiter(sp, s, regs, t->join_q.notification);
			sched_put(s);
		}
	} else {
		__sched_exec(sp, regs);
	}

	return regs;
}

size_t sched_sizeof(void)
{
	return sizeof(struct sched);
}

int sched_install(void *thrd, int policy, int priority)
{
	pid_t id = -1;
	struct sched *s = NULL;
	struct thread *t = thrd;

	if (!SCHED_VALID_POLICY(policy))
		return -EINVAL;

	if (!SCHED_VALID_PRIORITY(priority))
		return -EINVAL;

	id = sched_alloc_id();
	if (id < 0)
		return id;

	atomic_inc(&t->proc->alive);

	s = sched_of(t);

	memset(s, 0, sizeof(struct sched));

	INIT_LIST_HEAD(&s->ready_node);

	cpu_affinity_fill(s->affinity);

	/* bond the schedler/thread id */
	s->id = id;
	t->id = id;

	/* bond the sched/thread struct */
	s->thread = t;
	t->sched = s;

	s->policy = policy;
	s->priority = priority;
	s->prio = priority; /* sched_average_prio(s) */
	s->refc = 1;

	/* default set to suspend */
	s->state = SCHED_SUSPEND;

	s->magic = SCHED_STACK_MAGIC;

	sched_timer_init(s);

	sched_add(s);

	return 0;
}

bool sched_ready(pid_t id)
{
	unsigned long flags = 0;
	struct sched_priv *dst = NULL;
	struct sched_priv *currsp = NULL;
	struct thread_ctx *regs = NULL;
	struct sched_gd *gd = sched_gd();
	struct sched *s = sched_get_lock(id, &flags);

	/*
	 * sched entity offline
	 */
	if (s == NULL)
		return false;

	if (!list_empty(&s->ready_node)) {
		sched_put_lock(s, flags);
		return true;
	}

	/*
	 * pick the most suitable CPU
	 */
	currsp = sched_priv();
	dst = sched_pick_cpu(gd, currsp, s);

	/*
	 * 1. has binding to dedicated CPU
	 * 2. dst is the original CPU
	 */
	if (s->sp == dst)
		sched_enqueue(s);
	else
		sched_enqueue_on(s, dst);

	/*
	 * try to run the entity on the dst cpu ASAP
	 */
	if (s->sp == currsp) {
		regs = currsp->pc->int_ctx;
		if (regs && (s == sched_pick_next(currsp)))
			__sched_exec_specified(currsp, s, regs);
	} else if (s->sp->ready_num < 2)
		ipi_call_sched(s->sp->pc->id);

	sched_put_lock(s, flags);

	return true;
}

/*
 * Bind a just-created sched entity to a cpu,
 * the entity which is already running shall not
 * call this function any more.
 */
void sched_bind(pid_t id, int cpu)
{
	if (VALID_CPUID(cpu)) {
		unsigned long flags = 0;
		struct sched *s = sched_get_lock(id, &flags);
		struct sched_priv *src = NULL;
		struct sched_priv *dst = &__sched_priv[cpu];

		if (s) {
			src = s->sp;
			s->bind = true;
			cpu_affinity_zero(s->affinity);
			cpu_affinity_set(s->affinity, cpu);
			if (src != dst) {
				sched_sp_del(src, s);
				sched_sp_add(dst, s);
			}
			sched_put_lock(s, flags);
		}
	}
}

/*
 * Get the sched entity by ID,
 * increase the reference counter.
 * return the sched structure
 */
struct sched *sched_get(pid_t id)
{
	struct sched *s = NULL;
	struct sched_gd *gd = sched_gd();
	unsigned long flags = 0;

	if (!SCHED_ID_VALID(id))
		return NULL;

	spin_lock_irqsave(&gd->lock, flags);

	s = gd->scheds[id];
	if (s)
		s->refc++;

	spin_unlock_irqrestore(&gd->lock, flags);
	return s;
}

/*
 * Put the sched entity,
 * decrease the reference counter.
 */
void sched_put(struct sched *s)
{
	int cpu = 0;
	unsigned long flags = 0;
	struct sched_gd *gd = sched_gd();
	struct thread *t = NULL;

	if (s == NULL)
		return;

	if (sched_overflow(s))
		EMSG("%s stack overflow %d\n", s->thread->name, s->state);

	spin_lock_irqsave(&gd->lock, flags);

	assert(s->refc >= 1);

	if (--s->refc == 0) {
		if (!list_empty(&s->gd_node))
			_sched_uninstall(s);

		t = s->thread;
		t->sched = NULL;
		cpu = s->sp->pc->id;
		spin_unlock(&gd->lock);
		__schedule_highpri_work_on(cpu, &t->destroy);
		local_irq_restore(flags);
	} else {
		spin_unlock_irqrestore(&gd->lock, flags);
	}
}

/*
 * Get the sched entity by ID,
 * increase the reference counter,
 * achieve the global_desc (gd) lock.
 * return the sched structure
 */
struct sched *sched_get_lock(pid_t id, unsigned long *flg)
{
	struct sched *s = NULL;
	struct sched_gd *gd = sched_gd();
	unsigned long flags = 0;

	if (!SCHED_ID_VALID(id))
		return NULL;

	spin_lock_irqsave(&gd->lock, flags);
	s = gd->scheds[id];
	if (s) {
		s->refc++;
		*flg = flags;

		if (sched_overflow(s))
			EMSG("%s stack overflow %d\n", s->thread->name, s->state);
		return s;
	}
	spin_unlock_irqrestore(&gd->lock, flags);

	return NULL;
}

/*
 * Put the sched entity,
 * decrease the reference counter.
 * release the global_desc (gd) lock.
 */
void sched_put_lock(struct sched *s, unsigned long flags)
{
	int cpu = 0;
	struct sched_gd *gd = sched_gd();
	struct thread *t = NULL;

	if (s == NULL)
		return;

	if (sched_overflow(s))
		EMSG("%s stack overflow %d\n", s->thread->name, s->state);

	assert(s->refc >= 1);

	if (--s->refc == 0) {
		if (!list_empty(&s->gd_node))
			_sched_uninstall(s);

		t = s->thread;
		t->sched = NULL;
		cpu = s->sp->pc->id;
		spin_unlock(&gd->lock);
		__schedule_highpri_work_on(cpu, &t->destroy);
		local_irq_restore(flags);
	} else {
		spin_unlock_irqrestore(&gd->lock, flags);
	}
}

int sched_entry_init(pid_t id, void *entry,
	void *func, void *data)
{
	int ret = -ESRCH;
	unsigned long flags = 0;
	struct sched_priv *sp = NULL;
	struct thread *t = NULL;
	struct sched *s = sched_get_lock(id, &flags);

	if (s) {
		sp = s->sp;
		t = s->thread;

		spin_lock(&sp->lock);

		if (s->state != SCHED_SUSPEND)
			WMSG("%04d stat error - %s\n", s->id, sched_state(s->state));
		if (is_sigtpending(t))
			WMSG("%04d has pending signal\n", s->id);
		if (sighandling(t))
			WMSG("%04d sighandling %d\n", s->id, sighandling(t));

		if ((s->state == SCHED_SUSPEND) && !is_sigtpending(t)) {
			/* reset KC (kernel critical flag) */
			t->critical = 1;
			sp->archops->init_ctx(s, entry, func, data, 0);
			ret = 0;
		} else
			ret = -EPERM;

		spin_unlock(&sp->lock);
	}
	sched_put_lock(s, flags);

	return ret;
}

/*
 * User-space thread suspend itself via syscall
 */
void sched_suspend(struct thread_ctx *regs)
{
	struct sched_priv *sp = sched_priv();
	struct sched *s = sp->curr;
	struct thread *t = s->thread;
	unsigned long lastwords = regs->r[ARG_REG + 1];

	thread_leave_critical(t);

	/*
	 * has pending signals ? handle signals first
	 */
	if (is_sigtpending(t))
		schedule();

	mutex_lock(&t->mlock);

	s->s_stat = SCHED_SUSPENDING;
	t->join_q.notification = lastwords;
	schedule();
}

/*
 * User-space thread exits itself via syscall
 * running with current thread's stack
 */
void sched_exit(struct thread_ctx *regs)
{
	struct sched_priv *sp = sched_priv();
	struct sched *s = sp->curr;
	struct thread *t = s->thread;

	DMSG("UC %d KC %d I %d E %d sighandling %d wqnodes %d %d %d\n",
		t->tuser->critical, t->critical, t->tuser->inited, t->tuser->exiting,
		sighandling(t), !list_empty(&t->wqnodes),
		!list_empty(&t->join_q.list), !list_empty(&t->join_q.wakelist));

	s->s_stat = SCHED_EXITING;
	t->join_q.notification = regs->r[ARG_REG + 1];
	schedule();
}

void sched_wait(void)
{
	local_irq_disable();

	assert(in_interrupt() == false);

	sched_dequeue(sched_priv()->curr, SCHED_WAITING);
}

/*
 * call stack backtrace + exit
 */
static void sched_backtrace(void)
{
	struct sched_priv *sp = NULL;
	struct sched *s = NULL;
	struct thread *t = NULL;

	local_irq_disable();

	sp = sched_priv();

	s = sp->curr;
	if (s != NULL) {
		t = s->thread;
		if (t->proc == kproc()) {
			backtrace(); /* backtrace @ kernel */
			wakeup_notify(&t->join_q, -EFAULT);
			sched_kexit();
		} else {
			struct thread_ctx *uctx = sched_uregs(t);
			void (*setup_backtrace)(struct thread_ctx *regs, void *tracefn);

			setup_backtrace = sp->archops->setup_backtrace;
			void *utracefunc = t->proc->pself->wrapper.backtrace;

			backtrace(); /* backtrace @ kernel firstly */

			/* restore the original stack */
			sp->pc->thread_ksp = t->kstack = (void *)t + t->kstack_size;

			if (utracefunc) {
				memcpy(&s->regs, uctx, sizeof(struct thread_ctx));
				setup_backtrace(&s->regs, utracefunc);
			} else {
				t->critical = 0;
				t->tuser->critical = 0;
				sigenqueue(t->id, SIGKILL, SI_QUEUE,
					(union sigval)((void *)-EFAULT), true);
			}
			for (;;) {
				sched_clear_current(sp);
				schedule(); /* backtrace @ userspace */
			}
		}
	} else {
		backtrace(); /* backtrace @ kernel */
		schedule();
	}
}

static void sched_setup_abort(struct thread_ctx *regs,
	struct sched *curr)
{
	int back2app = false;
	struct sched_priv *sp = sched_priv();
	struct thread *t = curr->thread;
	struct process *proc = t->proc;
	void (*setup_backtrace)(struct thread_ctx *regs, void *tracefn);
	void *utracefunc = NULL;
	void *ktracefunc = NULL;

	curr->s_stat = SCHED_ABORT;

	setup_backtrace = sp->archops->setup_backtrace;
	utracefunc = proc->pself->wrapper.backtrace;

	if (user_addr(regs->pc)) {
		if (utracefunc)
			setup_backtrace(regs, utracefunc);
		else
			back2app = true;
	} else {
#ifdef CONFIG_BACKTRACE
		ktracefunc = sched_backtrace;
		/*
		 * enlarge the stack for backtrace(), backtrace uses huge stack,
		 * current regs->sp is too small that may overflow
		 */
		if (t->kstack_size < BACKTRACE_STACK_SIZE)
			t->brstack = kmalloc(BACKTRACE_STACK_SIZE);
		void *top = t->brstack ? t->brstack + BACKTRACE_STACK_SIZE
					: (void *)t + t->kstack_size;
		long inuse = (uintptr_t)t->kstack - regs->sp;

		if (t->kstack != top) {
			memmove(top - inuse, (void *)regs->sp, inuse);
			sp->pc->thread_ksp = t->kstack = top;
			regs->sp = (uintptr_t)top - inuse;
		}
#endif
		if (ktracefunc)
			setup_backtrace(regs, ktracefunc);
		else if (proc != kproc()) {
			if (utracefunc) {
				memmove(regs, sched_uregs(t), sizeof(*regs));
				setup_backtrace(regs, utracefunc);
			} else {
				back2app = true;
			}
		} else {
			sched_exit(regs);
		}
	}

	/*
	 * satisfy current thread's signal-needs
	 *
	 * back to the userspace and reclaim
	 * the resource for the user threads.
	 *
	 * SIGKILL will calls the pthread_exit(-ESRCH).
	 */
	if (back2app) {
		t->critical = 0;
		t->tuser->critical = 0;
		curr->s_stat = SCHED_EXITING;
		sigenqueue(t->id, SIGKILL, SI_QUEUE,
			(union sigval)((void *)-EFAULT), true);
	}
}

/*
 * handler for abort exceptions
 * -- thread aborts itself
 */
void sched_abort(struct thread_ctx *regs)
{
	struct sched_priv *sp = sched_priv();
	struct sched *curr = sp->curr;

	/* kernel early aborts ? */
	if (curr == NULL) {
		sp->archops->setup_backtrace(regs, sched_backtrace);
		return;
	}

	/* exit immediately for 2nd times aborts */
	if (curr->s_stat == SCHED_ABORT ||
		curr->s_stat == SCHED_EXITING) {
		sched_exit(regs);
	} else {
		/*
		 * setup backtrace or exit
		 */
		sched_setup_abort(regs, curr);
	}
}

/*
 * kthread exits itself
 */
void sched_kexit(void)
{
	struct sched *curr = NULL;

	local_irq_disable();

	curr = sched_priv()->curr;

	sched_dequeue(curr, SCHED_EXIT);
	sched_put(curr);
	schedule();
}

static inline void sched_update_user_priority(
	struct sched *s, int prio)
{
	/* update the userspace __pthread_self default priority */
	if (s->thread->tuser)
		s->thread->tuser->priority = prio;
}

static inline void sched_update_user_policy(
	struct sched *s, int policy)
{
	/* update the userspace __pthread_self default priority */
	if (s->thread->tuser)
		s->thread->tuser->policy = policy;
}

int sched_setscheduler(pid_t id, int policy,
	const struct sched_param *param)
{
	struct sched *s = NULL;
	struct sched_priv *sp = NULL;
	unsigned long flags = 0;

	if (!SCHED_VALID_POLICY(policy))
		return -EINVAL;

	if (!SCHED_VALID_PARAM(param))
		return -EINVAL;

	if (id == 0)
		id = current_id;
	else if (!SCHED_ID_VALID(id))
		return -ESRCH;

	s = sched_get_lock(id, &flags);
	if (!s)
		return -ESRCH;

	sp = s->sp;

	spin_lock(&sp->lock);
	s->policy = policy;
	s->priority = param->sched_priority;

	sched_update_user_priority(s, s->priority);
	sched_update_user_policy(s, policy);
	sched_change_prio(sp, s, s->priority);

	spin_unlock(&sp->lock);

	sched_put_lock(s, flags);
	return 0;
}

int sched_getscheduler(pid_t id)
{
	struct sched *s = NULL;
	int policy = 0;

	if (id == 0)
		id = current_id;
	else if (!SCHED_ID_VALID(id))
		return -ESRCH;

	s = sched_get(id);
	if (s == NULL)
		return -ESRCH;

	policy = s->policy;

	sched_put(s);
	return policy;
}

int sched_setparam(pid_t id,
	const struct sched_param *param)
{
	struct sched *s = NULL;
	struct sched_priv *sp = NULL;
	unsigned long flags = 0;

	if (!SCHED_VALID_PARAM(param))
		return -EINVAL;

	if (id == 0)
		id = current_id;
	else if (!SCHED_ID_VALID(id))
		return -ESRCH;

	s = sched_get_lock(id, &flags);
	if (s == NULL)
		return -ESRCH;

	sp = s->sp;
	spin_lock(&sp->lock);
	s->priority = param->sched_priority;
	sched_update_user_priority(s, s->priority);
	sched_change_prio(sp, s, s->priority);
	spin_unlock(&sp->lock);

	sched_put_lock(s, flags);
	return 0;
}

int sched_getparam(pid_t id,
	struct sched_param *param)
{
	struct sched *s = NULL;

	if (!param)
		return -EINVAL;

	if (id == 0)
		id = current_id;
	else if (!SCHED_ID_VALID(id))
		return -ESRCH;

	s = sched_get(id);
	if (!s)
		return -ESRCH;

	param->sched_priority = s->priority;

	sched_put(s);
	return 0;
}

int sched_setaffinity(pid_t id,
	size_t cpusetsize, const cpu_set_t *cpuset)
{
	int ret = 0;
	struct sched *s = NULL;
	struct sched_priv *sp = NULL;
	struct cpu_affinity backup, possible;
	unsigned long flags = 0;

	if (cpusetsize < sizeof(struct cpu_affinity))
		return -EINVAL;

	if (id == 0)
		id = current_id;
	else if (!SCHED_ID_VALID(id))
		return -ESRCH;

	s = sched_get_lock(id, &flags);
	if (s == NULL)
		return -ESRCH;

	sp = s->sp;
	spin_lock(&sp->lock);

	if (s->bind) {
		ret = -EINVAL;
		goto out;
	}

	cpu_affinity_and(&possible, cpus_online, (void *)cpuset);
	if (cpu_affinity_empty(&possible)) {
		ret = -EINVAL;
		goto out;
	}

	cpu_affinity_copy(&backup, s->affinity);

	cpu_affinity_copy(s->affinity, &possible);

	ret = __sched_switch_affinity_cpu(sp, s);
	if (ret != 0)
		cpu_affinity_copy(s->affinity, &backup);

out:
	spin_unlock(&sp->lock);
	sched_put_lock(s, flags);
	return ret;
}

int sched_getaffinity(pid_t id,
	size_t cpusetsize, cpu_set_t *cpuset)
{
	struct sched *s = NULL;
	struct sched_priv *sp = NULL;
	unsigned long flags = 0;

	if (cpusetsize < sizeof(struct cpu_affinity))
		return -EINVAL;

	if (id == 0)
		id = current_id;
	else if (!SCHED_ID_VALID(id))
		return -ESRCH;

	s = sched_get_lock(id, &flags);
	if (s == NULL)
		return -ESRCH;

	sp = s->sp;
	spin_lock(&sp->lock);
	memcpy(cpuset, s->affinity, sizeof(s->affinity));
	spin_unlock(&sp->lock);

	sched_put_lock(s, flags);
	return 0;
}

/*
 * always executes on CPU 0
 */
static int sched_str_suspend(void *data)
{
	struct sched_priv *sp = sched_priv();

	/*
	 * save the current sched context
	 */
	spin_lock(&sp->lock);
	sched_record_curr(sp->curr);
	sched_update_curr(sp, sp->curr);
	sp->archops->switch_ctx(sp->curr, sp->curr, sp->pc->int_ctx);
	sched_update_state(sp, sp->curr, NULL);
	sched_clear_current(sp);
	sp->pc->int_ctx = NULL;
	spin_unlock(&sp->lock);

	return 0;
}

static int sched_str_resume(void *data)
{
	struct sched *s = NULL;
	struct sched_gd *gd = data;
	unsigned long flags = 0;
	struct sched_priv *sp = sched_priv();

	spin_lock_irqsave(&gd->lock, flags);

	sp->lruntime = -1;
	sched_clear_current(sp);
	sp->stamp = read_cycles();

	/*
	 * re-init the stamp of each sched entity
	 */
	list_for_each_entry(s, &gd->sl, gd_node) {
		s->stamp = sp->stamp;
		s->lruntime = -1;
		s->runtime = 0;
	}

	spin_unlock_irqrestore(&gd->lock, flags);

	return 0;
}

static void sched_event(struct tevent *e)
{
	struct sched_priv *sp = sched_priv();

	__sched_exec(sp, sp->pc->int_ctx);

	sched_rotate(sp, SCHED_INTERVAL_USEC);
}

static void sched_ipi_event(void)
{
	struct sched_priv *sp = sched_priv();

	__sched_exec(sp, sp->pc->int_ctx);
}

/*
 * #sched_idx_max is calculated from mem_size(),
 * each MB can have 32 sched entities, the limited
 * range is (32 <= sched_idx_max <= 8192)
 */
unsigned int sched_idx_max = 128;
static void __init sched_gd_init(void)
{
	struct sched_gd *gd = sched_gd();

	spin_lock_init(&gd->lock);
	spin_lock_init(&gd->idle_lock);
	INIT_LIST_HEAD(&gd->sl);
	INIT_LIST_HEAD(&gd->cpus);
	INIT_LIST_HEAD(&gd->idle_cpus);

	sched_idx_max = (rounddown2pow(mem_size) >> 20) * 32;
	sched_idx_max = min(sched_idx_max, 8192u);

	gd->scheds = kzalloc(SCHED_ID_END * sizeof(struct sched *));

	assert(gd->scheds);

	assert(!ida_init(&gd->sched_ida, SCHED_ID_END));
	ida_set(&gd->sched_ida, 0);
}
EARLY_INIT_ROOT(sched_gd_init);

void sched_init(void)
{
	pid_t id = -1;
	struct sched_priv *sp = sched_priv();

	memset(sp->prio_bitmap, 0, sizeof(sp->prio_bitmap));

	for (id = SCHED_PRIO_MIN; id <= SCHED_PRIO_MAX; id++)
		INIT_LIST_HEAD(&sp->prio_lists[id]);

	INIT_LIST_HEAD(&sp->sl);
	INIT_LIST_HEAD(&sp->node);
	INIT_LIST_HEAD(&sp->idle_node);

	sp->pc = thiscpu;
	sp->threshold = msecs_to_cycles(SCHED_COUNT_PERIOD);
	sp->ready_num = 0;
	sp->total_num = 0;
	sp->rrprio = 0;
	sp->taskletd = NULL;
	sp->curr = NULL;
	sp->idle = NULL;
	sp->lruntime = -1;
	sp->stamp = read_cycles();
	sp->stamp_reward = sp->stamp;

	tevent_init(&sp->tevent, sched_event, sp);

	ipi_register(IPI_SCHED, (void *)sched_ipi_event);

	sched_arch_init(sp);
	sched_tasklet_init(sp);

	if (percpu_id() == 0)
		sched_cpu_online();

	sched_rotate(sp, SCHED_INTERVAL_USEC);
}

void sched_cpu_online(void)
{
	sched_cpu_add(sched_priv());
	cpu_set_online();
}

/*
 * For CPU Hot-Plug
 * save the current sched context
 */
static inline void sched_save_curr(struct sched_priv *sp)
{
	if (sp->curr) {
		sched_record_curr(sp->curr);
		sched_update_curr(sp, sp->curr);
		if (sp->pc->int_ctx) {
			sp->archops->switch_ctx(sp->curr,
				NULL, sp->pc->int_ctx);
		}
	}

	sp->pc->int_ctx = NULL;
	sched_clear_current(sp);
}

static void sched_init_exit(int cpu)
{
	usleep(100000);
	sched_kexit();
}

static void sched_isinit_exit(struct sched_priv *sp,
	struct sched *s)
{
	char initname[32];

	if (s->bind) {
		struct thread *t = s->thread;

		snprintf(initname, sizeof(initname), "init@%04d", t->id);

		if (!strcmp(t->name, initname) && !t->tuser) {
			IMSG("exiting %s\n", s->thread->name);
			sp->archops->init_ctx(s, sched_init_exit,
				(void *)(uintptr_t)percpu_id(),
				NULL, t->kstack_size >> 1);
		}
	}
}

/*
 * For CPU Hot-Plug
 * ~ migrating the sched entities to a live CPU
 */
void sched_migrating(void)
{
	struct sched *s = NULL;
	struct sched_gd *gd = sched_gd();
	struct sched_priv *sp = sched_priv();
	struct sched_priv *dst = NULL;

	spin_lock(&gd->lock);

	/*
	 * migrating the sched entities
	 */
	spin_lock(&sp->lock);
	while ((s = list_first_entry_or_null(&sp->sl,
				struct sched, node)) != NULL) {
		dst = __sched_pick_affinity_cpu(s, gd);

		if (dst == NULL)
			dst = __sched_pick_mostidle_cpu(gd);

		spin_lock(&dst->lock);

		__sched_sp_del(sp, s);

		IMSG("migrating %s - %d to CPU %d\n",
			s->thread->name, s->id, dst->pc->id);

		sched_isinit_exit(sp, s);

		if (!list_empty(&s->ready_node)) {
			sched_list_del(sp, s);

			if (s->state == SCHED_RUNNING)
				s->state = SCHED_READY;

			sched_list_add(dst, s);
			sched_idlecpu_dec(dst);
		}

		if (s->bind)
			cpu_affinity_zero(s->affinity);

		cpu_affinity_set(s->affinity, dst->pc->id);

		__sched_sp_add(dst, s);
		spin_unlock(&dst->lock);
	}
	spin_unlock(&sp->lock);
	spin_unlock(&gd->lock);

	tevent_stop(&sp->tevent);
}

/*
 * For CPU Hot-Plug
 * Force quit the un-necessary sched entities
 */
void sched_down(void)
{
	struct sched_priv *sp = sched_priv();

	sched_cpu_del(sp);

	sched_save_curr(sp);

	sched_tasklet_deinit(sp);
	sched_arch_deinit(sp);
}
DECLARE_STR(sched, sched_str_suspend, sched_str_resume, &__sched_gd);
