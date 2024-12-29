// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * sighandling @ scheduler
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
#include <errno.h>

#include "sched_timer.h"
#include "sched_record.h"
#include "sched_list.h"
#include "sched_priv.h"

#if defined(CONFIG_SIGNAL)

#define SIGEXEC_CONDI(t, regs) (pthread_isnt_critical((t)->tuser) && \
	(user_addr((regs)->pc) || thread_isnt_critical(t)))

pid_t sched_sigcheck(struct sched *s)
{
	struct thread *t = NULL;

	if (s) {
		t = s->thread;

		/*
		 * just roughly check if current thread
		 * should be continued or not, without sigp lock
		 */

		if (!list_empty(&s->gd_node) && list_empty(&s->ready_node) && t->tuser) {
			if (thread_isnt_critical(t) && is_sigtpending(t)) {
				if (t->tuser->inited && !t->tuser->exiting) {
					DMSG("%04d KC:%d UC:%d @ %s\n", s->id,
						t->critical, t->tuser->critical, t->name);
					return s->id;
				}
			}
		}
	}

	return 0;
}

/*
 * User-space thread suspend - via SIGSTOP
 */
static void *sched_sigstop(struct sched_priv *sp,
	struct sched *curr, struct thread_ctx *regs, long lastwords)
{
	struct thread *t = curr->thread;

	sched_dequeue(curr, SCHED_SUSPEND);

	/*
	 * backup current thread context
	 */
	spin_lock(&sp->lock);
	sp->archops->switch_ctx(curr, NULL, regs);
	/* change to a safe stack -> common_stack */
	if (is_thread_ksp(t, regs)) {
		regs = sp->pc->stack - sizeof(*regs);
		memcpy(regs, &curr->regs, sizeof(*regs));
	}
	spin_unlock(&sp->lock);

	/*
	 * runs to here, means current thread is running on a safe stack
	 *
	 * wakeup the waiters (REE or TEE waiters)
	 * switch to another thread
	 */
	sched_notify_waiter(sp, curr, regs, lastwords);

	return regs;
}

void *sched_sighandle(struct thread_ctx *regs)
{
	struct sched_priv *sp = sched_priv();
	struct sched *s = sp->curr;
	struct thread *t = NULL;
	struct signal_thread *sigt = NULL;
	struct signal_proc *sigp = NULL;
	struct sigarguments *sa = NULL;
	struct thread_ctx *uctx = NULL;
	int signo = 0;

	if (s == NULL)
		return regs;

	t = s->thread;
	sigt = &t->sigt;
	sigp = &t->proc->sigp;

	/* no signal is pending */
	if (atomic_read_x(&sigp->nrqueued) == 0)
		goto out;

	LMSG("pc %lx UC %d KC %d I %d exit %d ccnt %d pending %lx\n", regs->pc,
		t->tuser->critical, t->critical, t->tuser->inited, t->tuser->exiting,
		sigt->continuouscnt, *(long *)&sigt->pending);

	/* abort -> exiting */
	if (s->s_stat == SCHED_ABORT)
		goto out;

	if ((!t->tuser) || /* not an user thread */
		(!t->tuser->inited) || /* userspace not ready */
		(t->tuser->exiting)) /* already marked for death */
		goto out;

	/* share cpu timeslice for the original execution */
	if (sigt->continuouscnt >= 3)
		goto out;

	sa = &t->tuser->sa;
	while (SIGEXEC_CONDI(t, regs)) {
		signo = sigdequeue(t, &sigt->mask, &sa->info);
		if (signo == 0)
			break;

		t->tuser->sighandling = sigt->sighandling;

		if (signo == SIGCONT)
			continue;

		if (sigp->act[signo].sa_handler == SIG_IGN)
			continue;

		if (signo == SIGSTOP) {
			regs = sched_sigstop(sp, s, regs,
				(long)sa->info.si_value.sival_ptr);
			break;
		}

		sa->signo = signo;

		if (user_addr(regs->pc)) {
			uctx = regs;
			t->kstack -= sizeof(*regs);
			LMSG("NR:%d u signo %d kstack@%p regs@%p usp 0x%lx\n",
				sigp->nrqueued, signo, t->kstack, regs, regs->sp);
		} else {
			thread_enter_critical(t);
			uctx = sched_uregs(t);
			t->kstack = (void *)regs->sp - sizeof(*regs);
			LMSG("NR:%d k signo %d kstack@%p regs@%p usp 0x%lx\n",
				sigp->nrqueued, signo, t->kstack, regs, uctx->sp);
		}

		sp->archops->save_sigctx(s, regs);

		sp->archops->init_ctx(s,
			t->proc->pself->wrapper.signal_entry,
			sigp->act[signo].sa_handler,
			&t->tuser_uva->sa, ((uintptr_t)t->ustack_uva +
			t->ustack_size) - uctx->sp);

		sp->pc->thread_ksp = t->kstack;

		assert(!sched_overflow(s));

		return &s->regs;
	}

out:
	sigt->continuouscnt = 0;
	return regs;
}

void *sched_sigreturn(struct thread_ctx *regs)
{
	struct sched_priv *sp = sched_priv();
	struct sched *s = sp->curr;
	struct thread *t = s->thread;
	struct signal_thread *sigt = &t->sigt;

	LMSG("NR:%d signo %d kstack=%p regs=%p, stackmin=%p\n",
		t->proc->sigp.nrqueued, sigt->sighandling, t->kstack,
		regs, (void *)t + sizeof(*t));

	/* not return from a signal */
	assert(sigt->sighandling != 0);

	sigt->continuouscnt++;
	sigt->sighandling = 0;
	t->tuser->sighandling = 0;

	regs = t->kstack;

	sp->archops->restore_sigctx(s, regs);

	if (user_addr(regs->pc)) {
		t->kstack += sizeof(*regs);
	} else {
		t->kstack = (void *)t + t->kstack_size;
		thread_leave_critical(t);
	}

	sp->pc->thread_ksp = t->kstack;

	sigt->mask = sigt->savedmask;

	return regs;
}
#else

int sched_sigcheck(struct sched *s)
{
	return false;
}
void *sched_sighandle(struct thread_ctx *regs)
{
	return regs;
}
void *sched_sigreturn(struct thread_ctx *regs)
{
	return regs;
}

#endif
