// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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
	 * From: MIPSABI Position Independent Function Prologue
	 * The virtual address of a called function is passed
	 * to the function in general register $25, hereafter
	 * referred to by its software name t9. All callers of
	 * position independent functions must place the address
	 * of the called function in t9.
	 */
	regs->r[25] = regs->pc;
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
	if (t->tuser)
		t->tuser->cpuid = pc->id;

	/*
	 * Saw this reserved ASID, means OS was run out of the ASID,
	 * here need to clean the all indexed TLBs
	 */
	unsigned long asid = t->proc->pt->asid;
	/*
	 * Set the PROC specific information -> ASID
	 */
	pc->asid = asid;

	if (asid == ASID_RESVD)
		tlb_invalidate_all();
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
	return NULL;
}

static void sched_create_idle(struct sched_priv *sp)
{
	pid_t id = -1;
	struct sched_param p = {SCHED_PRIO_MIN};

	id = kthread_create_on(sched_idle, NULL, sp->pc->id, "idle");

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
