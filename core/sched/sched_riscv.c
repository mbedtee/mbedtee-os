// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * scheduler implementation @ RISCV32/RISCV64 related contexts
 */

#include <mmu.h>
#include <cpu.h>
#include <sched.h>
#include <trace.h>
#include <kthread.h>
#include <syscall.h>
#include <cacheops.h>
#include <riscv-mmu.h>

#include "sched_priv.h"

/*
 * Idle Thread Loop
 */
static void sched_idle(void *data)
{
	for (;;)
		asm volatile("wfi; nop" : : : "memory", "cc");
}

static void sched_init_ctx(struct sched *s,
	void *entry, void *func, void *data, long offsetsp)
{
	struct thread *t = s->thread;
	struct thread_ctx *regs = &s->regs;

#if defined(__riscv_flen)
	memset(regs, 0, offsetof(struct thread_ctx, f));
#else
	memset(regs, 0, sizeof(*regs));
#endif

	/*
	 * void entry{func(data)}
	 */
	regs->r[ARG_REG] = (unsigned long)func;
	regs->r[ARG_REG + 1] = (unsigned long)data;
	regs->pc = (unsigned long)entry;

	if (t->proc != kproc()) {
		/*
		 * user thread
		 */
		regs->sp = (unsigned long)t->ustack_uva + t->ustack_size - offsetsp;
		regs->tp = (unsigned long)t->tuser_uva;
		regs->stat = SR_PIE | SR_SUM | SR_MXR;
	} else {
		/*
		 * kernel thread
		 */
		regs->sp = (unsigned long)t + t->kstack_size - offsetsp;
		regs->tp = (unsigned long)t;
		regs->stat = SR_PIE | SR_SUM | SR_MXR | SR_PP;
		regs->gp = (unsigned long)&__global_pointer$;
	}

#if defined(CONFIG_MMU)
	struct pt_struct *pt = t->proc->pt;

	regs->satp = SATP_VAL(pt);

	if (pt != kpt()) {
		off_t o = (USER_VA_TOP >> PTD_SHIFT) * sizeof(ptd_t);

		memcpy(pt->ptds + o, kpt()->ptds + o, PT_SIZE - o);
	}
#endif
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
	if (t->tuser) {
		struct pt_struct *pt = t->proc->pt;

		t->tuser->cpuid = pc->id;

		/*
		 * Saw this reserved ASID, means OS was run out of the ASID,
		 * here need to clean the all indexed TLBs
		 */
		if (pt->asid == ASID_RESVD)
			local_flush_tlb_asid(pt->asid);
	}
#endif
}

#if defined(__riscv_flen)

static inline void __sched_link_fctx(struct percpu *pc,
	struct thread_ctx *dst)
{
	pc->fctx = dst;
	dst->fcpu = pc->id;
}

static void __sched_save_fctx(struct sched *s,
	struct thread_ctx *regs, struct thread_ctx *dst)
{
	if ((regs->stat & SR_FS) == SR_FS_DIRTY) {
		save_fpu_ctx(dst);
		regs->stat = (regs->stat & ~SR_FS) | SR_FS_CLEAN;
	} else {
		if (dst != &s->regs) {
			memcpy(dst->f, s->regs.f, sizeof(*regs) -
				offsetof(struct thread_ctx, f));
		}
	}

	__sched_link_fctx(thiscpu, dst);
}

static inline void __sched_restore_fctx(struct sched *s,
	struct thread_ctx *regs)
{
	struct percpu *pc = thiscpu;

	if ((regs->stat & SR_FS) != SR_FS_OFF) {
		if (pc->fctx != regs || regs->fcpu != pc->id) {
			__sched_link_fctx(pc, regs);
			restore_fpu_ctx(regs);
		}
	}
}

static inline void __sched_save_fuserctx(struct sched *s,
	struct thread_ctx *dst)
{
	if ((!dst->fusersaved) && (dst->stat & SR_FS)) {
		__sched_save_fctx(s, dst, dst);
		dst->fusersaved = true;
	}
}

void __sched_reset_fuserctx(void *t,
	struct thread_ctx *regs)
{
	struct sched *s = sched_of(t);

	memset(s->regs.f, 0, sizeof(*regs) -
			offsetof(struct thread_ctx, f));

	__sched_link_fctx(thiscpu, &s->regs);

	restore_fpu_ctx(&s->regs);

	regs->stat |= SR_FS_INIT;
}

void __sched_save_fabtctx(void *thd)
{
	struct thread *t = thd;

	if (t->tuser)
		__sched_save_fuserctx(sched_of(t), sched_uregs(t));
}

void __sched_restore_fuerctx(struct thread_ctx *regs)
{
	struct thread *t = current;

	/* FPU is dirty now ? (might be touched by kernel) */
	if ((regs->fusersaved == true) && user_addr(regs->pc)) {
		__sched_restore_fctx(sched_of(t), regs);
		regs->stat |= SR_FS_DIRTY;
	}
}
#endif

static void sched_save_sigctx(struct sched *s,
	struct thread_ctx *regs)
{
	struct thread_ctx *dst = s->thread->kstack;

#if defined(__riscv_flen)
	if (regs->stat & SR_FS) {
	/* the current fpu-ctx may not been saved ? */
		__sched_save_fctx(s, regs, dst);
	} else if (!user_addr(regs->pc)) {
	/* the last user-fpu-ctx may not been saved ? */
		__sched_save_fuserctx(s, thiscpu->thread_ksp - sizeof(*regs));
	}

	if (dst != regs)
		memcpy(dst, regs, offsetof(struct thread_ctx, f));
#else
	if (dst != regs)
		memcpy(dst, regs, sizeof(*regs));
#endif
}

static void sched_restore_sigctx(struct sched *s,
	struct thread_ctx *regs)
{
#if defined(__riscv_flen)
	if ((regs->stat & SR_FS) != SR_FS_OFF) {
		__sched_link_fctx(thiscpu, regs);
		restore_fpu_ctx(regs);
		memcpy(s->regs.f, regs->f, sizeof(*regs) -
				offsetof(struct thread_ctx, f));
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
#if defined(__riscv_flen)
	if (curr) {
		if (regs->stat & SR_FS)
			__sched_save_fctx(curr, regs, &curr->regs);
		else if (curr->thread->tuser && !user_addr(regs->pc))
			__sched_save_fuserctx(curr, sched_uregs(curr->thread));
		memcpy(&curr->regs, regs, offsetof(struct thread_ctx, f));
	}

	if (next) {
		memcpy(regs, &next->regs, offsetof(struct thread_ctx, f));

		__sched_restore_fctx(next, &next->regs);
		regs->fusersaved = false;

		sched_set_thread_mm(next);
	}
#else
	if (curr)
		memcpy(&curr->regs, regs, sizeof(*regs));

	if (next) {
		memcpy(regs, &next->regs, sizeof(*regs));
		sched_set_thread_mm(next);
	}
#endif
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
	if (id < 0) {
		EMSG("kthread_create failed %d\n", id);
		cpu_set_error();
	}

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
}

static const struct sched_arch riscv_sched_ops = {
	.pick = sched_pick_hook,
	.init_ctx = sched_init_ctx,
	.switch_ctx = sched_switch_ctx,
	.save_sigctx = sched_save_sigctx,
	.restore_sigctx = sched_restore_sigctx,
	.setup_backtrace = sched_setup_backtrace,
};

void sched_arch_init(struct sched_priv *sp)
{
	sp->archops = &riscv_sched_ops;
	sched_create_idle(sp);
}

void sched_arch_deinit(struct sched_priv *sp)
{
	sched_exit_idle(sp);
}
