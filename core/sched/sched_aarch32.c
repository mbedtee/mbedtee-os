// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * scheduler implementation @ AArch32@ARMV7-A contexts switch
 */

#include <mmu.h>
#include <sched.h>
#include <trace.h>
#include <kthread.h>
#include <syscall.h>

#include <aarch32-mmu.h>

#include "sched_priv.h"
#include "sched_list.h"

#define CONTEXT_ID_SHIFT (8)

/* CPACR: trap user VFP (cp10/cp11 = 01, privileged only) */
#define CPACR_VFP_TRAP_USR  (0x00500000UL)
/* CPACR: no trap VFP (cp10/cp11 = 11, full access) */
#define CPACR_VFP_NO_TRAP   (0x00F00000UL)

static inline void fpu_trap_enable(void)
{
	asm volatile("mcr p15, 0, %0, c1, c0, 2\n\tisb"
		: : "r" (CPACR_VFP_TRAP_USR) : "memory");
}

static inline void fpu_trap_disable(void)
{
	asm volatile("mcr p15, 0, %0, c1, c0, 2\n\tisb"
		: : "r" (CPACR_VFP_NO_TRAP) : "memory");
}

static void sched_idle(void *data)
{
	for (;;) {
#if defined(CONFIG_REE) /* ret to REE */
		smc_call(0, 0, 0, 0);
#else
		asm volatile("wfi; nop"
			: : : "memory", "cc");
#endif
	}
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

	if (IS_ENABLED(CONFIG_REE))
		sp->idle->regs.spsr |= IRQ_MASK | FIQ_MASK;
}

/*
 * IRQ assert when CPU state is secure, forward it to REE
 */
void *sched_exec_ree(struct thread_ctx *regs)
{
/* scheduler tick interval for REE IRQ */
#define SCHED_IRQ_FORWARD_NS (500000UL) /* Nano-seconds */

	struct sched_priv *sp = sched_priv();
	struct sched *next = sp->idle;
	struct timespec time;

	__sched_exec_specified(sp, next, regs);

	/*
	 * REE IRQ is so frequent,
	 * shall reduce the REE timeslice
	 * on the IRQ_FORWARD mode.
	 */
	time.tv_sec = 0;
	time.tv_nsec = SCHED_IRQ_FORWARD_NS;
	tevent_renew(&sp->tevent, &time);

	return regs;
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
		regs->spsr = USR_MODE | ASYNC_ABT_MASK;
		regs->ttbr0 = MMU_TTBR(t->proc->pt);
		regs->tpidrurw = (unsigned long)t->tuser_uva;
		regs->context_id = (t->proc->id << CONTEXT_ID_SHIFT) | t->proc->pt->asid;
#endif
	} else {
		/* kernel thread */
		regs->sp = (unsigned long)t + t->kstack_size - offsetsp;
		regs->spsr = SYS_MODE | ASYNC_ABT_MASK;

		/* Mask the NS-IRQ for taskletd to ensure the taskletd priority */
		if (sched_tasklet_routine == func)
			regs->spsr |= IRQ_MASK;
	}

	/*
	 * For ARM32 AAPCS, va_arg(ap, uint64_t) requires
	 * the stack pointer (SP) aligned to 8 bytes.
	 */
	regs->sp = regs->sp & ~7UL;

#if !defined(CONFIG_IRQ_FORWARD)
	regs->spsr |= IRQ_MASK;
#endif

	/*
	 * current executing thread
	 */
	regs->tpidruro = (unsigned long)t;

	/* lazy FPU: link sched_ctx for FPU trap restore */
	t->sched_ctx = regs;
}

/* set the thread and MM info to global */
static void sched_set_thread_mm(struct sched *s)
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
	if (curr)
		memcpy(&curr->regs, regs, GPR_CTX_SIZE);

	if (next) {
		memcpy(regs, &next->regs, GPR_CTX_SIZE);
		/* Enable user VFP trap for lazy restore */
		thiscpu->fpu_owner = NULL;
		fpu_trap_enable();
		sched_set_thread_mm(next);
	}
}

static void sched_save_sigctx(struct sched *s,
	struct thread_ctx *regs)
{
	struct thread_ctx *dst = s->thread->kstack;

	/* Copy GPR first: signal frame may overlap exception frame */
	if (dst != regs)
		memcpy(dst, regs, GPR_CTX_SIZE);

	/* Copy FPU from sched->regs (saved by save_fpu_ctx_eager at entry) */
	memcpy((char *)dst + GPR_CTX_SIZE,
		(char *)&s->regs + GPR_CTX_SIZE, FPU_CTX_SIZE);
}

static void sched_restore_sigctx(struct sched *s,
	struct thread_ctx *regs)
{
	/*
	 * Copy FPU state from saved signal context back to sched->regs.
	 * The physical D registers will be lazily restored on next FPU use.
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

/*
 * For CPU Hot-Plug
 * exit the virtual ree thread sched entity if exist
 * or exit the idle sched entity if CONFIG_REE not set
 */
static void sched_exit_ree_or_idle(struct sched_priv *sp)
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
	sched_exit_ree_or_idle(sp);
}
