/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * scheduler private definitions
 */

#ifndef _SCHED_PRIV_H
#define _SCHED_PRIV_H

#include <ctx.h>
#include <ipi.h>
#include <wait.h>
#include <timer.h>
#include <errno.h>
#include <sched.h>
#include <tevent.h>
#include <bitops.h>
#include <percpu.h>
#include <thread.h>
#include <tasklet.h>
#include <affinity.h>
#include <uaccess.h>
#include <kmalloc.h>
#include <ksignal.h>

/*
 * 1 ~ (sched_idx_max - 1), 0 is reserved
 *
 * #sched_idx_max is calculated from mem_size(),
 * each MB can have 16 sched entities, the limited
 * range is (32 <= sched_idx_max <= 8192)
 */
#define SCHED_ID_START			(1)
#define SCHED_ID_END			(sched_idx_max)
#define SCHED_ID_VALID(_x_)	\
	(((_x_) >= SCHED_ID_START) && ((_x_) < SCHED_ID_END))

/*
 * Define the state constants
 */
#define SCHED_SUSPEND	(0x00)
#define SCHED_EXIT		(0x01)
#define SCHED_WAITING	(0x02)
#define SCHED_SLEEPING	(0x03)
#define SCHED_READY		(0x04)
#define SCHED_RUNNING	(0x05)
#define SCHED_STAT_MAX	(0x06)

/*
 * thread specific scheduler information
 */
struct sched {
	/*
	 * ready-node in scheduler prior_list
	 * DO NOT MOVE, 'node' shall be the first
	 * variable to enhance the scheduling performance,
	 * offsetof(struct sched, node) can be skiped
	 */
	struct list_head ready_node;

	/* node in percpu sched entities list */
	struct list_head node;

	/* node in global sched entities list */
	struct list_head gd_node;

	/* sched entity ID */
	pid_t id;

	/* reference counter */
	int refc;

	/* scheduler priority */
	int8_t priority;
	/* current priority */
	int8_t prio;

	/* scheduler policy SCHED_FIFO/SCHED_RR/SCHED_OTHER */
	uint8_t policy;
	/* already been bound to a dedicate cpu or not */
	bool bind;
	/* regular states: SCHED_RUNNING and SCHED_WAITING etc.. */
	uint8_t state;

	/* special states: abort state, intermediate state of suspend/exit */
#define SCHED_ABORT 1
#define SCHED_SUSPENDING 2
#define SCHED_EXITING 3
	uint8_t s_stat;

	struct cpu_affinity affinity[1];

	struct thread *thread;

	/* scheduler private data for one processor */
	struct sched_priv *sp;

	/* timer event for sched_timeout() */
	struct tevent tevent;

	/* actual timeslice(in cycles) of current counting */
	uint32_t runtime;
	/* actual timeslice(in cycles) of last counting */
	uint32_t lruntime;
	/* total timeslice(in cycles)since born */
	uint64_t overall;
	/* start cyclestamp of current counting */
	uint64_t stamp;

	/* Registers of the thread */
	struct thread_ctx regs;

	/*
	 * consumed priority (in cycles)
	 * SCHED_OTHER policy will auto-decrease the
	 * priority after the thread consumed CPU timeslice.
	 * 'prio_consumed' desides how many levels the
	 * priority will be decreased.
	 */
	uint32_t prio_consumed;

	/* magic num for stack overflow checking */
	uint32_t magic;
} __aligned(sizeof(long));

#define SCHED_STACK_MAGIC (0x01060511)

/*
 * stack overflow checking
 */
static inline bool sched_overflow(void *s)
{
	return (((struct sched *)s)->magic != SCHED_STACK_MAGIC);
}

/*
 * scheduler global data for multi-processors
 */
struct sched_gd {
	/* protecting enqueue/dequeue operations of each sched-entity */
	struct spinlock lock;

	/* only for protecting the idle_cpus list */
	struct spinlock idle_lock;

	/* For the sched-entity IDs */
	struct ida sched_ida;

	/*
	 * contains all threads' scheduler info
	 */
	struct sched **scheds;
	struct list_head sl;

	/*
	 * alive cpu list
	 */
	struct list_head cpus;

	/*
	 * idle cpu list.
	 */
	struct list_head idle_cpus;
};

struct sched_priv;

/*
 * scheduler -- architecture related functions
 */
struct sched_arch {
	void (*init_ctx)(struct sched *s,
		void *entry, void *func, void *data, long offsetsp);
	void (*switch_ctx)(struct sched *curr,
		struct sched *next,	struct thread_ctx *regs);
	void (*save_sigctx)(struct sched *s, struct thread_ctx *regs);
	void (*restore_sigctx)(struct sched *s, struct thread_ctx *regs);
	void (*setup_backtrace)(struct thread_ctx *regs, void *tracefunc);

	struct sched *(*pick)(struct sched_priv *sp);
};

/*
 * scheduler private data for one processor
 */
struct sched_priv {
	/* current thread */
	struct sched *curr;
	/* idle thread */
	struct sched *idle;

	/* scheduler cycling/tick timer event */
	struct tevent tevent;

	const struct sched_arch *archops;

	struct percpu *pc;

	/*
	 * percpu sched entities list.
	 */
	struct list_head sl;

	/*
	 * node in the gd alive cpu list.
	 */
	struct list_head node;

	/*
	 * node in the gd idle cpu list.
	 */
	struct list_head idle_node;

	/*
	 * percpu tasklets list.
	 * when we have multi-softints in the future,
	 * we can change this variable to the 'softriqs' array,
	 * and add bitmap to manage multi-softints
	 */
	struct list_head tasklets;
	/* percpu tasklets daemon */
	struct sched *taskletd;

	uint16_t ready_num;
	uint16_t total_num;

	/* percpu round-robin priority ceiling */
	uint16_t rrprio;

	struct spinlock lock;

	/* elapsed time of last counting window */
	uint32_t lruntime;
	/* time window width threshold of each counting */
	uint32_t threshold;
	/* start timestamp of current counting window */
	uint64_t stamp;
	/* start timestamp of current reward-prio counting window */
	uint64_t stamp_reward;

	/* Lists for priorities */
	struct list_head prio_lists[SCHED_PRIO_MAX + 1];
	unsigned long prio_bitmap[(SCHED_PRIO_MAX + 1) / BITS_PER_LONG];
};

void sched_arch_init(struct sched_priv *sp);
void sched_arch_deinit(struct sched_priv *sp);
void sched_tasklet_init(struct sched_priv *sp);
void sched_tasklet_deinit(struct sched_priv *sp);
void sched_tasklet_routine(void *data);

void sched_notify_waiter(
	struct sched_priv *sp, struct sched *s,
	struct thread_ctx *regs, long lastwords);

pid_t sched_sigcheck(struct sched *s);

/*
 * Get the sched entity by ID,
 * increase the reference counter.
 * return the sched structure
 */
struct sched *sched_get(pid_t id);

/*
 * Put the sched entity,
 * decrease the reference counter.
 */
void sched_put(struct sched *s);

void __sched_exec(struct sched_priv *sp, struct thread_ctx *regs);

void __sched_exec_specified(struct sched_priv *sp,
	struct sched *next, struct thread_ctx *regs);

/*
 * Get the sched entity by ID,
 * increase the reference counter,
 * achieve the global_desc (gd) lock.
 * return the sched structure
 */
struct sched *sched_get_lock(pid_t id, unsigned long *flags);
/*
 * Put the sched entity,
 * decrease the reference counter.
 * release the global_desc (gd) lock.
 */
void sched_put_lock(struct sched *s, unsigned long flags);

/*
 * dequeue a sched entity from its CPU's scheduler list
 *
 * compare to sched_queue(), this function sets
 * a wakeup timer, this timer event wakes up this
 * sched entity after the timeout elapsed
 */
void sched_timed_dequeue(struct sched *s,
	int state, struct timespec *time);

/*
 * dequeue a sched entity from its CPU's scheduler list
 */
void sched_dequeue(struct sched *s, int state);

#define sched_of(t) ((struct sched *)((struct thread *)t + 1))

#define sched_uregs(t) ((struct thread_ctx *)((t)->kstack - sizeof(struct thread_ctx)))

#define is_thread_ksp(t, addr) (((unsigned long)(addr) > (unsigned long)(t)) && \
	((unsigned long)(addr) < (unsigned long)(t)->kstack))

extern struct sched_priv __sched_priv[CONFIG_NR_CPUS];
static inline struct sched_priv *sched_priv(void)
{
	return &__sched_priv[percpu_id()];
}

static inline struct sched_gd *sched_gd(void)
{
	extern struct sched_gd __sched_gd;

	return &__sched_gd;
}

static inline void sched_clear_current(struct sched_priv *sp)
{
	sp->curr = NULL;
	set_current(kthread());
}

static inline const char *sched_state(int stat)
{
	static const char * const state_str[] = {
		"Suspend", "Exiting", "Waiting",
		"Sleep", "Ready", "Running"
	};

	return state_str[stat];
}

static inline unsigned long sched_hold_all(
	struct sched_gd *gd)
{
	struct sched_priv *sp = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&gd->lock, flags);

	list_for_each_entry(sp, &gd->cpus, node)
		spin_lock(&sp->lock);

	return flags;
}

static inline void sched_put_all(struct sched_gd *gd,
	unsigned long flags)
{
	struct sched_priv *sp = NULL;

	list_for_each_entry(sp, &gd->cpus, node)
		spin_unlock(&sp->lock);

	spin_unlock_irqrestore(&gd->lock, flags);
}

#endif
