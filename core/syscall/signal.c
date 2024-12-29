// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Signal related
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <reent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#include <timer.h>
#include <uaccess.h>
#include <strmisc.h>
#include <syscall.h>
#include <trace.h>
#include <thread.h>
#include <ksignal.h>
#include <kmalloc.h>

#include <__pthread.h>

#if defined(CONFIG_SIGNAL)

#define PRIORMASK (~(1ul << SIGKILL | 1ul << SIGCANCEL | \
		1ul << SIGSTOP | 1ul << SIGCONT))

static void __sigdropign(struct list_head *h, sigset_t *pending, int signo)
{
	struct sigqueue *q = NULL, *n = NULL;

	if (!sigismember(pending, signo))
		return;

	sigdelset(pending, signo);
	list_for_each_entry_safe(q, n, h, node) {
		if (q->info.si_signo == signo) {
			list_del(&q->node);
			kfree(q);
		}
	}
}

static void sigdropign(struct process *p, int signo)
{
	struct thread *t = NULL;
	struct signal_proc *sigp = &p->sigp;

	__sigdropign(&sigp->queue, &sigp->pending, signo);

	spin_lock(&p->slock);
	list_for_each_entry(t, &p->threads, node) {
		__sigdropign(&t->sigt.queue, &t->sigt.pending, signo);
	}
	spin_unlock(&p->slock);
}


int sigaction(int signo, const struct sigaction *act, struct sigaction *oldact)
{
	struct process *proc = current->proc;
	struct signal_proc *sigp = &proc->sigp;
	unsigned long flags = 0;
	struct sigaction *sa = NULL;

	if (signo < 1 || signo >= NSIG)
		return -EINVAL;

	if (signo == SIGKILL || signo == SIGSTOP || signo == SIGCANCEL)
		return -EINVAL;

	if (act && !user_addr(act->sa_handler))
		return -EFAULT;

	spin_lock_irqsave(&sigp->lock, flags);
	sa = &sigp->act[signo];

	if (oldact)
		*oldact = *sa;

	if (act) {
		*sa = *act;

		sa->sa_mask &= PRIORMASK;

		/*
		 * discard the pending IGN signal, whether or not it is blocked.
		 */
		if (sa->sa_handler == SIG_IGN)
			sigdropign(proc, signo);
	}
	spin_unlock_irqrestore(&sigp->lock, flags);

	return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	struct thread *t = current;
	struct signal_thread *sigt = &t->sigt;
	struct signal_proc *sigp = &t->proc->sigp;
	unsigned long flags = 0;
	sigset_t newset;

/*
 *	sigprocmask() is used to fetch and/or change the signal mask of
 *	the calling thread.  The signal mask is the set of signals whose
 *	delivery is currently blocked for the caller (see also signal(7)
 *	for more details).
 *
 *	Each of the threads in a process has its own signal mask.
 */
	if (oldset)
		*oldset = sigt->mask;

	if (set) {
		switch (how) {
		case SIG_BLOCK:
			newset = sigt->mask | (*set);
			break;
		case SIG_UNBLOCK:
			newset = sigt->mask & ~(*set);
			break;
		case SIG_SETMASK:
			newset = *set;
			break;
		default:
			return -EINVAL;
		}

		newset &= PRIORMASK;

		spin_lock_irqsave(&sigp->lock, flags);
		sigt->mask = newset;
		spin_unlock_irqrestore(&sigp->lock, flags);
	}

	return 0;
}

static bool sigwakeupthread(struct thread *t, int signo)
{
	struct signal_thread *sigt = &t->sigt;

	if (!sigismember(&sigt->mask, signo) ||
		sigismember(&sigt->sigwait, signo)) {
		sched_ready(t->id);
		return true;
	}
	return false;
}

static inline int __sigenqueue(struct signal_proc *sigp,
	struct list_head *h, sigset_t *pending, siginfo_t *info)
{
	int signo = info->si_signo;
	struct sigqueue *q = NULL;

	q = kmalloc(sizeof(*q));
	if (q == NULL) {
		EMSG("allocate failed signo %d code %d\n", signo, info->si_code);
		return -EAGAIN;
	}

	q->info = *info;

	sigp->nrqueued++;

	if (signo == SIGKILL || signo == SIGSTOP || signo == SIGCANCEL)
		list_add(&q->node, h);
	else
		list_add_tail(&q->node, h);

	sigaddset(pending, signo);

	return 0;
}

static int sigbroadcastkillstop(struct process *proc,
	siginfo_t *info)
{
	int ret = 0;
	struct thread *t = NULL;
	struct signal_thread *sigt = NULL;

	spin_lock(&proc->slock);
	list_for_each_entry(t, &proc->threads, node) {
		sigt = &t->sigt;
		if (!t->tuser->exiting && (sigt->sighandling != info->si_signo)) {
			if (!sigismember(&sigt->pending, info->si_signo))
				ret |= __sigenqueue(&proc->sigp, &sigt->queue, &sigt->pending, info);
			sched_ready(t->id);
		} else if (info->si_signo == SIGKILL)
			sched_ready(t->id);
	}
	spin_unlock(&proc->slock);

	return t ? ret : -ESRCH;
}

/* pthread_kill / pthread_sigqueue - send signal to specific thread - #tid */
static int sigenqueue_t(pid_t tid, siginfo_t *info)
{
	unsigned long flags = 0;
	int ret = -1, signo = info->si_signo;
	struct thread *t = thread_get(tid);
	struct process *p = NULL;
	struct signal_thread *sigt = NULL;
	struct signal_proc *sigp = NULL;

	if (t == NULL)
		return -ESRCH;

	if (t->tuser->exiting) {
		ret = -ESRCH;
		goto out;
	}

	if (signo == 0) {
		ret = 0;
		goto out;
	}

	p = t->proc;
	sigt = &t->sigt;
	sigp = &p->sigp;

	spin_lock_irqsave(&sigp->lock, flags);

	/* killed, not necessary to enqueue any others */
	if (sigismember(&sigt->pending, SIGKILL)) {
		ret = 0;
		goto outl;
	}

	if (sigismember(&sigt->pending, SIGCANCEL) && (signo != SIGKILL)) {
		ret = 0;
		goto outl;
	}

	/* only permit one pending sig for kill()/Timer-Sigev etc. */
	if (sigismember(&sigt->pending, signo)) {
		if (info->si_code == SI_USER) {
			ret = 0;
			goto outl;
		} else if (info->si_code == SI_TIMER) {
			ret = -EAGAIN;
			goto outl;
		}
	}

	/* limit to #MAX_NUMOF_QUEUED */
	if (sigp->nrqueued >= MAX_NUMOF_QUEUED) {
		EMSG("drop signal %d for %s@%04d - limit=%d\n",
			signo, p->c->name, p->id, MAX_NUMOF_QUEUED);
		sigwakeupthread(t, signo);
		ret = -EAGAIN;
		goto outl;
	}

	/*
	 * always enqueue the blocked signo, due to the handler
	 * may change by the time it's unblocked
	 */
	if (sigismember(&sigt->mask, signo) || (sigp->act[signo].sa_handler != SIG_IGN)) {
		ret = __sigenqueue(sigp, &sigt->queue, &sigt->pending, info);
		if (ret == 0)
			sigwakeupthread(t, signo);
		else
			goto outl;
	}

	ret = 0;

outl:
	spin_unlock_irqrestore(&sigp->lock, flags);
out:
	thread_put(t);
	return ret;
}

static void sigmaskofproc(struct process *proc,
	sigset_t *mask)
{
	struct thread *t = NULL;
	sigset_t set;

	sigemptyset(&set);

	spin_lock(&proc->slock);
	list_for_each_entry(t, &proc->threads, node) {
		if (!t->tuser->exiting)
			set |= ~t->sigt.mask;
	}
	spin_unlock(&proc->slock);
	*mask = ~set;
}

static void sigwakeupproc(struct process *proc, int signo)
{
	struct thread *t = NULL;

	spin_lock(&proc->slock);
	list_for_each_entry(t, &proc->threads, node) {
		if (!t->tuser->exiting && !t->sigt.sighandling) {
			if (sigwakeupthread(t, signo))
				break;
		}
	}
	spin_unlock(&proc->slock);
}

/* kill / sigqueue - send signal to specific process - #p */
static int sigenqueue_p(struct process *p, siginfo_t *info)
{
	int ret = -1, signo = info->si_signo;
	struct signal_proc *sigp = &p->sigp;
	unsigned long flags = 0;
	sigset_t mask;

	if (signo == 0)
		return 0;

	/* reserved signo, same as SIGKILL when process-wide */
	if (signo == SIGCANCEL)
		signo = SIGKILL;

	spin_lock_irqsave(&sigp->lock, flags);

	/* only permit one pending sig for kill() or Timer-Sigev etc. */
	if (sigismember(&sigp->pending, signo)) {
		if (info->si_code == SI_USER) {
			ret = 0;
			goto outl;
		} else if (info->si_code == SI_TIMER) {
			ret = -EAGAIN;
			goto outl;
		}
	}

	/* limit to #MAX_NUMOF_QUEUED */
	if (sigp->nrqueued >= MAX_NUMOF_QUEUED) {
		EMSG("drop signal %d for %s@%04d - limit=%d\n",
			signo, p->c->name, p->id, MAX_NUMOF_QUEUED);
		sigwakeupproc(p, signo);
		ret = -EAGAIN;
		goto outl;
	}

	/*
	 * always enqueue the blocked signo, due to the handler
	 * may change by the time it's unblocked
	 */
	sigmaskofproc(p, &mask);
	if (sigismember(&mask, signo) || (sigp->act[signo].sa_handler != SIG_IGN)) {
		if (signo == SIGKILL || signo == SIGSTOP || signo == SIGCONT)
			ret = sigbroadcastkillstop(p, info);
		else {
			ret = __sigenqueue(sigp, &sigp->queue, &sigp->pending, info);
			if (ret == 0)
				sigwakeupproc(p, signo);
		}

		if (ret != 0)
			goto outl;

	}

	ret = 0;

outl:
	spin_unlock_irqrestore(&sigp->lock, flags);
	return ret;
}

static int sigsecuritycheck(struct process *dst, bool threaddirected)
{
	int ret = -EPERM;
	struct process *proc = current->proc;

	/* kernel thread/proc do not allow signal */
	if (dst == kproc())
		goto err;

	/* threads in same process always has the permission */
	if (dst == proc)
		ret = 0;
	/* parent process always has the permission */
	else if (proc->id == dst->parent_id)
		ret = 0;
	/* privileged process always has the permission */
	else if (proc->c->privilege)
		ret = 0;
	/*
	 * check if current TA has permission
	 * to access the target TA
	 */
	else if (!threaddirected && strstr_delimiter(
		proc->c->ipc_acl, dst->c->name, ','))
		ret = 0;

err:
	if (ret != 0)
		DMSG("sigcheck pid %04d ret %d\n", dst->id, ret);
	return ret;
}

int sigenqueue(pid_t id, int signo, int sigcause,
	const union sigval value, bool threaddirected)
{
	int ret = -EINVAL;
	siginfo_t info = {signo, sigcause, value};
	struct process *dst = process_get(id);

	if (dst == NULL)
		return -ESRCH;

	ret = sigsecuritycheck(dst, threaddirected);
	if (ret != 0)
		goto out;

	DMSG("Send signal %d to %04d %d\n", signo, id, threaddirected);

	if ((unsigned int)signo >= NSIG)
		goto out;

	if (threaddirected)
		ret = sigenqueue_t(id, &info);
	else
		ret = sigenqueue_p(dst, &info);

out:
	process_put(dst);
	return ret;
}

static int __sigdequeue(struct signal_proc *sigp,
	struct signal_thread *sigt, sigset_t *mask,
	siginfo_t *info, bool threaddirected)
{
	sigset_t val, *pending = NULL;
	int signo = 0, __signo = 0, priorsigno = 0, handling = 0;
	struct sigqueue *q = NULL, *n = NULL, *multiq = NULL;
	struct list_head *h = NULL;

	pending = threaddirected ? &sigt->pending : &sigp->pending;

	val = *pending & ~*mask;

	if (val) {
		handling = sigt->sighandling;

		if (handling == SIGKILL || handling == SIGCANCEL)
			return 0;

		if (sigismember(&val, SIGKILL))
			priorsigno = SIGKILL;
		else if (sigismember(&val, SIGCANCEL))
			priorsigno = SIGCANCEL;
		else if (sigismember(&val, SIGSTOP))
			priorsigno = SIGSTOP;
		else if (handling == SIGSTOP && sigismember(&val, SIGCONT))
			priorsigno = SIGCONT;

		if (!priorsigno && handling)
			return 0;

		h = threaddirected ? &sigt->queue : &sigp->queue;

		/* SIGKILL > SIGCANCEL > SIGSTOP always the prior signals */
		if (priorsigno) {
			list_for_each_entry(n, h, node) {
				__signo = n->info.si_signo;
				if (__signo == signo) {
					multiq = n;
					break;
				}
				if (__signo == priorsigno) {
					signo = __signo;
					q = n;
				}
			}
		} else {
			list_for_each_entry(n, h, node) {
				__signo = n->info.si_signo;
				if (__signo == signo) {
					multiq = n;
					break;
				}
				if (sigismember(&val, __signo)) {
					signo = __signo;
					q = n;
				}
			}
		}

		list_del(&q->node);

		if (multiq == NULL)
			sigdelset(pending, signo);

		if (info)
			*info = q->info;

		sigp->nrqueued--;

		sigt->sighandling = (signo != SIGCONT) ? signo : sigt->siglast;
		sigt->siglast = (signo != SIGSTOP) ? 0 : handling;

		if (signo != SIGCONT) {
			if (!handling)
				sigt->savedmask = sigt->mask;
			sigt->mask = PRIORMASK;
		} else {
			if (handling)
				sigt->mask = sigt->savedmask;
		}

		kfree(q);
	}

	return signo;
}

/* pick a signal, return signo and siginfo */
int sigdequeue(struct thread *t, sigset_t *mask, siginfo_t *info)
{
	int signo = 0;
	unsigned long flags = 0;
	struct signal_thread *sigt = &t->sigt;
	struct signal_proc *sigp = &t->proc->sigp;

	spin_lock_irqsave(&sigp->lock, flags);

	signo = __sigdequeue(sigp, sigt, mask, info, true);
	if (!signo)
		signo = __sigdequeue(sigp, sigt, mask, info, false);

	spin_unlock_irqrestore(&sigp->lock, flags);
	return signo;
}

int sigpending(sigset_t *set)
{
	struct thread *t = current;
	struct signal_proc *sigp = NULL;
	struct signal_thread *sigt = NULL;
	unsigned long flags = 0;
	sigset_t unionset;

/*
 *	A thread can obtain the set of signals that it currently has
 *	pending using sigpending(2).  This set will consist of the union
 *	of the set of pending process-directed signals and the set of
 *	signals pending for the calling thread.
 */
	if (set == NULL)
		return -EFAULT;

	sigt = &t->sigt;
	sigp = &t->proc->sigp;

	spin_lock_irqsave(&sigp->lock, flags);
	unionset = sigt->pending | sigp->pending;
	unionset &= sigt->mask;
	spin_unlock_irqrestore(&sigp->lock, flags);

	*set = unionset;
	return 0;
}

int sigaltstack(const stack_t *ss, stack_t *old_ss)
{
	return -ENOTSUP;
}

int sigtimedwait(const sigset_t *set,
	siginfo_t *info, const struct timespec *ts)
{
	struct thread *t = current;
	struct process *p = t->proc;
	struct signal_proc *sigp = NULL;
	struct signal_thread *sigt = NULL;
	unsigned long flags = 0;
	uint64_t timeusecs = INT_MAX;
	sigset_t waitset = *set, mask;
	int signo = 0;

	if (set == NULL)
		return -EINVAL;

	if (ts) {
		if (INVALID_TIMESPEC(ts))
			return -EINVAL;
		timeusecs = time_to_usecs(ts);
	}

	waitset &= PRIORMASK;

	sigt = &t->sigt;
	sigp = &p->sigp;

	spin_lock_irqsave(&sigp->lock, flags);
	sigt->sigwait = waitset;
	mask = ~waitset;
	do {
		timeusecs = !ts ? INT_MAX : timeusecs;
		signo = __sigdequeue(sigp, sigt, &mask, info, true);
		if (!signo)
			signo = __sigdequeue(sigp, sigt, &mask, info, false);

		if (signo)
			sigt->sighandling = 0;

		if (signo || !timeusecs)
			break;

		timeusecs = sched_timeout_locked(&sigp->lock, timeusecs, true);
	} while (1);

	sigemptyset(&sigt->sigwait);
	spin_unlock_irqrestore(&sigp->lock, flags);

	if (signo)
		return signo;

	return timeusecs ? -EINTR : -EAGAIN;
}

int sigsuspend(const sigset_t *set)
{
	struct thread *t = current;
	struct signal_thread *sigt = &t->sigt;
	struct signal_proc *sigp = &t->proc->sigp;
	struct timespec waitts = {INT64_MAX >> 1, 0};
	sigset_t mask, orimask;

	if (!set)
		return -EFAULT;

	mask = *set & PRIORMASK;

	spin_lock_irq(&sigp->lock);

	orimask = sigt->mask;
	sigt->mask = mask;

	if (is_sigpending(t))
		waitts.tv_sec = 0;

/*
 *	If the signal is caught, then sigsuspend() returns after
 *	the signal handler returns, and the signal mask is restored to
 *	the state before the call to sigsuspend()
 */

	sched_timespec_locked(&sigp->lock, &waitts, true);

	sigt->mask = orimask;

	spin_unlock(&sigp->lock);

	return -EINTR;
}

int pause(void)
{
/*
 *	pause() returns only when a signal was caught and the signal-
 *	catching function returned.  In this case, pause() returns -1,
 *	and errno is set to EINTR
 */
	struct thread *t = current;
	struct signal_proc *sigp = &t->proc->sigp;
	struct timespec waitts = {INT64_MAX >> 1, 0};

	spin_lock_irq(&sigp->lock);

	if (is_sigpending(t))
		waitts.tv_sec = 0;

	sched_timespec_locked(&sigp->lock, &waitts, true);

	spin_unlock(&sigp->lock);

	return -EINTR;
}

/*
 * init the signal_thread struct
 */
int sigt_init(struct thread *t)
{
	struct signal_thread *sigt = &t->sigt;

	INIT_LIST_HEAD(&sigt->queue);

	return 0;
}

int sigt_free(struct thread *t)
{
	struct signal_thread *sigt = &t->sigt;
	struct signal_proc *sigp = &t->proc->sigp;
	struct sigqueue *q = NULL, *n = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&sigp->lock, flags);

	list_for_each_entry_safe(q, n, &sigt->queue, node) {
		__list_del_entry(&q->node);
		DMSG("free signo %d @ %s\n", q->info.si_signo, t->name);
		kfree(q);
	}

	spin_unlock_irqrestore(&sigp->lock, flags);

	return 0;
}

/*
 * init the signal_proc struct
 */
int sigp_init(struct process *proc)
{
	struct signal_proc *sigp = &proc->sigp;

	INIT_LIST_HEAD(&sigp->queue);

/*
 * SIG_DFL is defined as NULL, so we can skip this init
 *	for (int i = 0; i < NSIG; i++)
 *		sigp->act[i].sa_handler = (void *)SIG_DFL;
 */

	return 0;
}

int sigp_free(struct process *p)
{
	struct signal_proc *sigp = &p->sigp;
	struct sigqueue *q = NULL, *n = NULL;

	list_for_each_entry_safe(q, n, &sigp->queue, node) {
		__list_del_entry(&q->node);
		DMSG("free signo %d @ %04d\n", q->info.si_signo, p->id);
		kfree(q);
	}

	return 0;
}

#else

int sigenqueue(pid_t id, int signo, int sigcause,
	const union sigval value, bool threaddirected)
{
	return -ENOTSUP;
}

int sigdequeue(struct thread *t, sigset_t *mask, siginfo_t *info)
{
	return 0;
}

int sigaction(int signo, const struct sigaction *act, struct sigaction *oldact)
{
	return -ENOTSUP;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	return -ENOTSUP;
}

int sigpending(sigset_t *set)
{
	return 0;
}

int sigaltstack(const stack_t *ss, stack_t *old_ss)
{
	return -ENOTSUP;
}

int sigtimedwait(const sigset_t *set,
	siginfo_t *info, const struct timespec *ts)
{
	return -ENOTSUP;
}

int sigsuspend(const sigset_t *set)
{
	return -ENOTSUP;
}

int pause(void)
{
	return -ENOTSUP;
}

int sigt_init(struct thread *t) { return 0; }
int sigt_free(struct thread *t) { return 0; }
int sigp_init(struct process *proc) { return 0; }
int sigp_free(struct process *proc) { return 0; }

#endif
