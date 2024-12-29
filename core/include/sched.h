/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#ifndef _SCHED_H
#define _SCHED_H

#include <ctx.h>
#include <cpuset.h>
#include <percpu.h>
#include <power.h>
#include <sys/types.h>
#include <sys/sched.h>
#include <spinlock.h>
#include <mutex.h>

/*
 * Define the priorities
 * 0 ~ 39 for user threads, default: 16
 * 0 ~ 63 for kernel threads, default: 44

 * larger value has higher priority
 */
#define SCHED_PRIO_MAX				(63)
#define SCHED_PRIO_MIN				(0)
#define SCHED_PRIO_DEFAULT			(44)
#define SCHED_HIGHPRIO_DEFAULT		(48)

#define SCHED_PRIO_USER_MAX			(39)
#define SCHED_PRIO_USER_MIN			(0)

#define SCHED_VALID_PRIORITY(_x_)	\
		(((_x_) >= SCHED_PRIO_MIN) && \
		((_x_) <= SCHED_PRIO_MAX))

#define SCHED_VALID_PARAM(p)	\
		((p) && SCHED_VALID_PRIORITY((p)->sched_priority))
#define SCHED_VALID_USER_PARAM(p)	\
		(((p.sched_priority) >= SCHED_PRIO_USER_MIN) && \
		((p.sched_priority) <= SCHED_PRIO_USER_MAX))

#define SCHED_VALID_POLICY(_x_)	\
		(((_x_) == SCHED_OTHER) || \
		((_x_) == SCHED_FIFO) || \
		((_x_) == SCHED_RR))
#define SCHED_VALID_USER_POLICY(_x_)	\
		(((_x_) == SCHED_OTHER) || \
		((_x_) == SCHED_FIFO) || \
		((_x_) == SCHED_RR))

extern unsigned int sched_idx_max;

size_t sched_sizeof(void);

/*
 * active/online this scheduler/cpu
 */
void sched_cpu_online(void);

/*
 * Set the policy and priority for the thread specified by pid
 */
int sched_setscheduler(pid_t pid, int policy,
	const struct sched_param *param);

/*
 * Get the policy of the thread specified by pid
 */
int sched_getscheduler(pid_t pid);

/*
 * Set the priority for the thread specified by pid
 */
int sched_setparam(pid_t pid, const struct sched_param *param);

/*
 * Get the priority of the thread specified by pid
 */
int sched_getparam(pid_t pid, struct sched_param *param);

int sched_setaffinity(pid_t id,
	size_t cpusetsize, const cpu_set_t *cpuset);

int sched_getaffinity(pid_t id,
	size_t cpusetsize, cpu_set_t *cpuset);

/* yield the processor to other threads */
void schedule(void);

/* init the scheduler */
void sched_init(void);

/* the caller enters waiting mode */
void sched_wait(void);

/* the kthread caller exits itself */
void sched_kexit(void);

/* ready this sched entity (thread) */
bool sched_ready(pid_t id);

/*
 * Bind a just-created sched entity to a cpu,
 * the entity which is already running shall not
 * call this func any more.
 */
void sched_bind(pid_t id, int cpu);

/* user-space thread exits itself via syscall */
void sched_exit(struct thread_ctx *regs);

/*
 * user-space thread suspends itself via syscall
 * suspend current thread and send lastwords to its waiters
 */
void sched_suspend(struct thread_ctx *regs);

/* specific handler for abort exception handlers */
void sched_abort(struct thread_ctx *regs);

void *sched_exec(struct thread_ctx *regs);

/*
 * run REE client
 */
void *sched_exec_ree(struct thread_ctx *regs);

/*
 * Create client virtual thread with the specific ctx
 */
void sched_create_ree_thread(struct thread_ctx *ctx);

/* install scheduler for thread */
int sched_install(void *t, int policy, int priority);

/*
 * uninstall sched structure, only for the entity
 * which has not been scheduled (just installed)
 */
void sched_uninstall(void *sched_t);

/* Set the user-thread/kthread entry function */
int sched_entry_init(pid_t id, void *entry,
	void *func, void *data);

/* Free the sched entity ID */
void sched_free_id(pid_t id);

/*
 * This calling thread sleeps for
 * given number of milliseconds.
 *
 * Returns:
 * 0 if the timeout(msecs) elapsed,
 * remaining msecs if the caller has been
 * waked up before timeout elapsed.
 */
uint64_t sched_msecs(uint64_t msecs);

/*
 * This calling thread sleeps for
 * given number of microseconds.
 *
 * Returns:
 * 0 if the timeout(microseconds) elapsed,
 * remaining microseconds if the caller has been
 * waked up before timeout elapsed.
 */
uint64_t sched_usecs(uint64_t usecs);

/*
 * This calling thread sleeps for given timespec
 *
 * Returns via #time
 * time.tv_sec may be negative if the timeout elapsed
 */
void sched_timespec(struct timespec *time);

/*
 * This function starts the timeout timer,
 * and sets the thread state to waiting.
 *
 * spinlock is held before dequeue finish to avoid race-condition
 *
 * Returns via #time
 * time.tv_sec may be negative if the timeout elapsed
 */
void sched_timespec_locked(struct spinlock *lock,
	struct timespec *time, int interruptible);

/*
 * This calling thread waits for given number of microseconds.
 *
 * spinlock is held before dequeue finish to avoid race-condition
 *
 * Returns:
 * 0 if the timeout(microseconds) elapsed,
 * remaining microseconds if the caller has been
 * waked up before timeout elapsed.
 */
uint64_t sched_timeout_locked(struct spinlock *lock,
	uint64_t usecs, int interruptible);

/*
 * This function starts the timeout timer,
 * and sets the thread state to waiting.
 *
 * mutexlock/spinlock are held before dequeue finish to avoid race-condition
 *
 * Returns via #time
 * time.tv_sec may be negative if the timeout elapsed
 */
void sched_timespec_mutex_locked
(
	struct mutex *mlock, struct spinlock *slock,
	struct timespec *time, int interruptible
);

/*
 * This calling thread waits for given number of microseconds.
 *
 * mutexlock/spinlock are held before dequeue finish to avoid race-condition
 *
 * Returns:
 * 0 if the timeout(microseconds) elapsed,
 * remaining microseconds if the caller has been
 * waked up before timeout elapsed.
 */
uint64_t sched_timeout_mutex_locked
(
	struct mutex *mlock, struct spinlock *slock,
	uint64_t usecs, int interruptible
);

void sched_client_retval(int ret);

/*
 * target 'id' inherits the run-time prio of the sched entity #s.
 *
 * ceiling priority policy for the mutex and semaphores
 */
int sched_inherit_prio(void *s, pid_t id);
int sched_resume_prio(pid_t id);

/*
 * Usually For CPU Hot-Plug
 * pick a suitable alive cpu (usually the most idle one)
 */
int sched_pick_mostidle_cpu(void);

/*
 * Get the CPU time consumed by this thread/process
 */
void __sched_thread_cputime(void *t, struct timespec *tval);
int sched_thread_cputime(pid_t tid, struct timespec *tval);
int sched_process_cputime(pid_t tid, struct timespec *tval);

void *sched_sighandle(struct thread_ctx *regs);
void *sched_sigreturn(struct thread_ctx *regs);

/*
 * For CPU Hot-Plug
 * Force quit the un-necessary sched entities
 */
void sched_down(void);
/*
 * For CPU Hot-Plug
 * ~ migrating the sched entities to a live CPU
 */
void sched_migrating(void);

#endif
