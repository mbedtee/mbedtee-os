// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * scheduler implementation @ MIPS32 related contexts
 */

#include <mmu.h>
#include <cpu.h>
#include <sched.h>
#include <trace.h>
#include <kthread.h>
#include <syscall.h>

#include <mips32-mmu.h>
#include <mips32-tlb.h>

#include "sched_priv.h"

/*
 * Idle Thread Loop
 */
static void sched_idle(void *data)
{
	for (;;) {
		asm volatile(
			".set push\n"
			".set noreorder\n"
			"wait;nop\n"
			".set pop\n"
			: : : "memory", "cc");
	}
}

static void sched_init_ctx(struct sched *s,
	void *entry, void *func, void *data, long offsetsp)
{
	struct thread *t = s->thread;
	struct thread_ctx *regs = &s->regs;

	memset(regs, 0, sizeof(*regs));

	/*
	 * void entry{func(data)}
	 */
	regs->r[ARG_REG] = (unsigned long)func;
	regs->r[ARG_REG + 1] = (unsigned long)data;
	regs->pc = (unsigned long)entry;

	/*
	 * sp is $29
	 */
	if (t->proc != kproc()) {
		/*
		 * user thread
		 */
		regs->sp = (unsigned long)t->ustack_uva + t->ustack_size - offsetsp;
		regs->stat = read_cp0_register(C0_STATUS) & ~STAT_MASK;
		regs->stat |= STAT_IE | STAT_EXL | STAT_USER;
		regs->userlocal = (unsigned long)t->tuser_uva;
	} else {
		/*
		 * kernel thread
		 */
		regs->sp = (unsigned long)t + t->kstack_size - offsetsp;
		regs->stat = read_cp0_register(C0_STATUS) & ~STAT_MASK;
		regs->stat |= STAT_IE | STAT_EXL;
		regs->userlocal = (unsigned long)t;
	}

	/*
	 * Ensure 8-byte alignment for MIPS O32 ABI.
	 *
	 * Signal delivery inherits the interrupted user SP which
	 * may be only 4-byte aligned mid-function. sdc1 (store
	 * double) requires 8-byte alignment, so round down.
	 *
	 * The extra 16-byte reservation guards against the GCC
	 * callee pattern: "addiu sp,sp,-N" / "sw v0,N(sp)".
	 */
	regs->sp = (regs->sp - 16) & ~7UL;

	/*
	 * From: MIPSABI Position Independent Function Prologue
	 * The virtual address of a called function is passed
	 * to the function in general register $25, hereafter
	 * referred to by its software name t9. All callers of
	 * position independent functions must place the address
	 * of the called function in t9.
	 */
	regs->r[25] = regs->pc;

	/* lazy FPU: link sched_ctx for FPU trap restore */
	t->sched_ctx = regs;
}

/* set the thread and MM info to global */
static inline void sched_set_thread_mm(struct sched *s)
{
	struct thread *t = s->thread;
	struct percpu *pc = thiscpu;

	/*
	 * Set the Thread specific information
	 *
	 * Set to current thread
	 *
	 * Set the user thread's kernel stack
	 * (PERCPU_THREAD_KSP is only useful for user threads)
	 */
	pc->current_thread = t;
	pc->thread_ksp = t->kstack;

	set_current(t);

#if defined(CONFIG_MMU)
	{
		unsigned long asid = 0;

		if (t->tuser)
			t->tuser->cpuid = pc->id;

		/*
		 * Saw this reserved ASID, means OS was run out of the ASID,
		 * here we need to clean all indexed TLBs
		 */
		asid = t->proc->pt->asid;
		/*
		 * Set the PROC specific information -> ASID
		 */
		pc->asid = asid;

		if (asid == ASID_RESVD)
			tlb_invalidate_all();
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
		sched_set_thread_mm(next);

#if defined(CONFIG_FPU)
		/* Trap FPU - lazy restore on first access */
		thiscpu->fpu_owner = NULL;
		/*
		 * Clear CU1 in CP0_Status so that any FPU access from
		 * user mode triggers a CpU exception (cause = 11).
		 */
		write_cp0_register(C0_STATUS, read_cp0_register(C0_STATUS) & ~STAT_CU1);
#endif
	}
}

static void sched_save_sigctx(struct sched *s,
	struct thread_ctx *regs)
{
	struct thread_ctx *dst = s->thread->kstack;

	/* Copy GPR from exception frame */
	if (dst != regs)
		memcpy(dst, regs, GPR_CTX_SIZE);

	if (IS_ENABLED(CONFIG_FPU)) {
		/* Copy FPU from sched->regs (saved by save_fpu_ctx_eager at entry) */
		memcpy((char *)dst + GPR_CTX_SIZE,
			(char *)&s->regs + GPR_CTX_SIZE, FPU_CTX_SIZE);
		/*
		 * On the CpU trap -> signal path, cpu_handler() set
		 * fpu_owner and CU1 *after* save_fpu_ctx_eager() had
		 * already run.  Clear both so the thread takes a clean
		 * CpU trap on its next FPU access after sigreturn,
		 * reloading from s->regs (restored by restore_sigctx).
		 */
		if (thiscpu->fpu_owner == s->thread) {
			thiscpu->fpu_owner = NULL;
			dst->stat &= ~STAT_CU1;
		}
	}
}

static void sched_restore_sigctx(struct sched *s,
	struct thread_ctx *regs)
{
	if (IS_ENABLED(CONFIG_FPU)) {
		/*
		 * Copy FPU state from saved signal context back to sched->regs.
		 * The physical FP registers will be lazily restored on next FPU use.
		 */
		memcpy((char *)&s->regs + GPR_CTX_SIZE,
			(char *)regs + GPR_CTX_SIZE, FPU_CTX_SIZE);
	}
}

static struct sched *sched_pick_hook(struct sched_priv *sp)
{
	return NULL;
}

static void sched_create_idle(struct sched_priv *sp)
{
	pid_t id = -1;
	struct sched_param p = {SCHED_PRIO_MIN};

	id = kthread_create_on((void *)sched_idle, NULL, sp->pc->id, "idle");

	assert(id > 0);

	sched_setscheduler(id, SCHED_RR, &p);

	sp->idle = sched_gd()->scheds[id];
}

/*
 * For CPU Hot-Plug
 */
static void sched_exit_idle(struct sched_priv *sp)
{
	struct sched *s = sp->idle;

	sp->idle = NULL;
	sched_dequeue(s, SCHED_EXIT);
	sched_put(s);
}

static void sched_setup_backtrace(
	struct thread_ctx *regs, void *tracefunc)
{
	regs->lr = regs->pc;
	regs->pc = (unsigned long)tracefunc;
	regs->r[25] = regs->pc;
}

static const struct sched_arch mips32_sched_ops = {
	.pick = sched_pick_hook,
	.init_ctx = sched_init_ctx,
	.switch_ctx = sched_switch_ctx,
	.save_sigctx = sched_save_sigctx,
	.restore_sigctx = sched_restore_sigctx,
	.setup_backtrace = sched_setup_backtrace,
};

void sched_arch_init(struct sched_priv *sp)
{
	sp->archops = &mips32_sched_ops;
	sched_create_idle(sp);
}

void sched_arch_deinit(struct sched_priv *sp)
{
	sched_exit_idle(sp);
}
