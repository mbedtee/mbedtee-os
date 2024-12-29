// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * scheduler implementation @ AArch64 contexts switch
 */

#include <mmu.h>
#include <sched.h>
#include <trace.h>
#include <kthread.h>
#include <syscall.h>
#include <interrupt.h>

#include <aarch64-mmu.h>

#include "sched_priv.h"

static void sched_idle(void *data)
{
	for (;;) {
#ifdef CONFIG_REE /* ret to REE */
		smc_call(0, 0, 0, 0);
#else
		asm volatile("wfi; nop" : : : "memory", "cc");
#endif
	}
}

static void sched_init_ctx(struct sched *s,
	void *entry, void *func, void *data, long offsetsp)
{
	struct thread *t = s->thread;
	struct thread_ctx *regs = &s->regs;

	memset(regs, 0, sizeof(*regs));

	regs->r[ARG_REG] = (unsigned long)func;
	regs->r[ARG_REG + 1] = (unsigned long)data;
	regs->pc = (unsigned long)entry;

	if (t->proc != kproc()) {
#if defined(CONFIG_USER)
		/* user thread */
		regs->sp = (unsigned long)t->ustack_uva + t->ustack_size - offsetsp;
		regs->spsr = SPSR_MODE_EL0T | SPSR_ASYNC_MASK | SPSR_DEBUG_MASK;
		regs->tpidr_el0 = (unsigned long)t->tuser_uva;
		regs->ttbr0_el1 = MMU_TTBR(t->proc->pt);
#endif
	} else {
		/* kernel thread */
		regs->sp = (unsigned long)t + t->kstack_size - offsetsp;
		regs->spsr = SPSR_MODE_EL1T | SPSR_ASYNC_MASK | SPSR_DEBUG_MASK;
	}

	regs->contextidr_el1 = t->proc->id;

	/*
	 * current executing thread
	 */
	regs->tpidrro_el0 = (unsigned long)t;
}

/* set the thread and MM info to global */
static inline void sched_set_thread_mm(struct sched *s)
{
	struct thread *t = s->thread;
	struct percpu *pc = thiscpu;

	/*
	 * Set the thread's kernel stack -> PERCPU_THREAD_KSP
	 * (only useful for user threads)
	 */
	pc->thread_ksp = t->kstack;

	set_current(t);

#if defined(CONFIG_MMU)
	if (t->tuser)
		t->tuser->cpuid = pc->id;

	/*
	 * Saw this reserved ASID, means OS was run out of the ASID,
	 * here need to clean the TLBs indexed by this ASID on each context switch,
	 * because this ASID might be used on different applications
	 */
	unsigned long asid = t->proc->pt->asid;

	if (asid == ASID_RESVD)
		flush_tlb_asid(asid);
#endif
}

static void sched_switch_ctx
(
	struct sched *curr,
	struct sched *next,
	struct thread_ctx *regs
)
{
	if (curr)
		memcpy(&curr->regs, regs, sizeof(*regs));

	if (next) {
		memcpy(regs, &next->regs, sizeof(*regs));
		sched_set_thread_mm(next);
	}
}

static void sched_save_sigctx(struct sched *s,
	struct thread_ctx *regs)
{
	struct thread_ctx *dst = s->thread->kstack;

	if (dst != regs)
		memcpy(dst, regs, sizeof(*regs));
}

static void sched_restore_sigctx(struct sched *s,
	struct thread_ctx *regs)
{

}

static struct sched *sched_pick_hook(struct sched_priv *sp)
{
#ifdef CONFIG_REE
	struct sched *s = sp->idle;

	/*
	 * Give a chance to run the REE, avoid the REE jamming
	 */
	if (s && (s->runtime < CYCLES_PER_MSECS))
		return s;
#endif
	return NULL;
}

static void sched_create_idle(struct sched_priv *sp)
{
	pid_t id = -1;
	struct sched_param p = {SCHED_PRIO_MIN};

	id = kthread_create_on(sched_idle,
			NULL, sp->pc->id, "idle");
	if (id < 0) {
		EMSG("kthread_create failed %d\n", id);
		cpu_set_error();
	}

	sched_setscheduler(id, SCHED_RR, &p);

	sp->idle = sched_gd()->scheds[id];
}

/*
 * For CPU Hot-Plug
 * exit the sched idle entity
 */
static void sched_exit_idle(struct sched_priv *sp)
{
	struct sched *s = sp->idle;

	if (s == NULL)
		return;

	sp->idle = NULL;
	sched_dequeue(s, SCHED_EXIT);
	sched_put(s);
}

static void sched_setup_backtrace(
	struct thread_ctx *regs, void *tracefunc)
{
	regs->lr = regs->pc;
	regs->pc = (unsigned long)tracefunc;
}

static const struct sched_arch sched_ops = {
	.pick = sched_pick_hook,
	.init_ctx = sched_init_ctx,
	.switch_ctx = sched_switch_ctx,
	.save_sigctx = sched_save_sigctx,
	.restore_sigctx = sched_restore_sigctx,
	.setup_backtrace = sched_setup_backtrace,
};

void sched_arch_init(struct sched_priv *sp)
{
	sp->archops = &sched_ops;
	sched_create_idle(sp);
}

/*
 * For CPU Hot-Plug
 */
void sched_arch_deinit(struct sched_priv *sp)
{
	sched_exit_idle(sp);
}
