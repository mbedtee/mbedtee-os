// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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

/* CPACR_EL1.FPEN: trap EL0 FPU, allow EL1 */
#define CPACR_FPEN_TRAP_EL0 ((3UL << 16) | (1UL << 20))
/* CPACR_EL1.FPEN: no trap */
#define CPACR_FPEN_NO_TRAP  ((3UL << 16) | (3UL << 20))

static inline void fpu_trap_enable(void)
{
	asm volatile("msr cpacr_el1, %0\n\tisb"
		: : "r" (CPACR_FPEN_TRAP_EL0) : "memory");
}

static inline void fpu_trap_disable(void)
{
	asm volatile("msr cpacr_el1, %0\n\tisb"
		: : "r" (CPACR_FPEN_NO_TRAP) : "memory");
}

static void sched_idle(void *data)
{
	for (;;) {
	if (IS_ENABLED(CONFIG_REE)) /* ret to REE */
		smc_call(0, 0, 0, 0);
	else
		asm volatile("wfi; nop" : : : "memory", "cc");
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

	/* lazy FPU: back-pointer for FPU trap restore */
	t->sched_ctx = regs;
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
	{
		unsigned long asid = 0;

		if (t->tuser)
			t->tuser->cpuid = pc->id;

		/*
		 * Saw this reserved ASID, means OS was run out of the ASID,
		 * here we need to clean the TLBs indexed by this ASID on each context switch,
		 * because this ASID might be used on different applications
		 */
		asid = t->proc->pt->asid;

		if (asid == ASID_RESVD)
			flush_tlb_asid(asid);
	}
#endif
}

static void sched_switch_ctx
(
	struct sched *curr,
	struct sched *next,
	struct thread_ctx *regs
)
{
	if (curr) {
		/* Save only GPR portion from exception stack */
		memcpy(&curr->regs, regs, GPR_CTX_SIZE);
	}

	if (next) {
		/* Restore only GPR portion to exception stack */
		memcpy(regs, &next->regs, GPR_CTX_SIZE);
		sched_set_thread_mm(next);

		/* Trap EL0 FPU - lazy restore on first access */
		thiscpu->fpu_owner = NULL;
		fpu_trap_enable();
	}
}

static void sched_save_sigctx(struct sched *s,
	struct thread_ctx *regs)
{
	struct thread_ctx *dst = s->thread->kstack;

	/* Copy GPR from exception frame */
	if (dst != regs)
		memcpy(dst, regs, GPR_CTX_SIZE);

	/* Copy FPU from sched->regs (saved by kernel_fpu_eagersave at entry) */
	memcpy((char *)dst + GPR_CTX_SIZE,
		(char *)&s->regs + GPR_CTX_SIZE, FPU_CTX_SIZE);
}

static void sched_restore_sigctx(struct sched *s,
	struct thread_ctx *regs)
{
	/*
	 * Copy FPU state from saved signal context back to sched->regs.
	 * The physical Q registers will be lazily restored on next FPU use.
	 */
	memcpy((char *)&s->regs + GPR_CTX_SIZE,
		(char *)regs + GPR_CTX_SIZE, FPU_CTX_SIZE);
}

static struct sched *sched_pick_hook(struct sched_priv *sp)
{
#if defined(CONFIG_REE)
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

	id = kthread_create_on((void *)sched_idle,
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

	if (!s)
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
