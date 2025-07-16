/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Process structures
 */

#ifndef _PROCESS_H
#define _PROCESS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ida.h>
#include <mem.h>
#include <page.h>
#include <file.h>
#include <sched.h>
#include <mutex.h>
#include <kproc.h>
#include <ksignal.h>
#include <__process.h>
#include <process_config.h>

#define MAX_ARGV_NUM (256)
#define MAX_ARGV_SIZE (1024 * 1024)
#define MAX_ARGSTR_SIZE (256 * 1024)

#define PROCESS_ENTRY_LEN (64)

/* 32 ~ 8192 */
#define PROCESS_THREAD_MAX (sched_idx_max)

/* 512 ~ (memsize in MB * 64) */
#define PROCESS_FD_MAX ((mem_size >> 14) > NUMFD_PER_POOL ? \
			(mem_size >> 14) : NUMFD_PER_POOL)

struct argv {
	int argc;
	void *uva;
	char *pages[];
};

/*
 * process structure
 */
struct process {
	/* Process ID */
	pid_t id;

	/* Parent's pid */
	pid_t parent_id;

	/* node in process list */
	struct list_head node;

	/* Process Configuration */
	struct process_config *c;

	/* Process's main() function pointer */
	void *main_func;

	/* Process's FD table */
	struct fdtab fdt;

	/* Process's private mutex */
	struct mutex mlock;

	/* Process's private spinlock */
	struct spinlock slock;

	/* reference counter */
	int refc;
	/* alive stat (negative means proc is exiting) */
	struct atomic_num alive;

	/* waitpid() bookkeeping (minimal) */
	struct atomic_num wait_state;
	long exit_code; /* raw _exit() value */
	/* list of its threads (include exiting thread) */
	struct list_head threads;

	/* Child process management */
	struct list_head children;  /* head of child process list */
	struct list_head sibling;   /* node in parent's children list */

	/* list of its utimers */
	struct list_head utimers;

	/* consumed time of its exited threads */
	struct timespec runtime;

	/* Process's memory maps via mmap() syscall */
	struct list_head mmaps;

	/* ASLR addend */
	unsigned long aslr;

	/* loaded ELF object */
	struct elf_obj *obj;

	/* process's page table entity */
	struct pt_struct *pt;

	struct argv *argv;

	/* process's VMA space for TEE memory */
	struct vma *vm;
	/* process's VMA space for REE memory */
	struct vma *vm4ree;

	/* Process userspace wrapper functions (@libc) */
	struct process_wrapper wrapper;
	/* Process's Global Platform functions (@app) */
	struct process_gp gp;
	/* information for unwind backtrace */
	struct unwind_info unwind;

	/* Libc heap page list (UserSpace Heap) */
	struct list_head heap_pages;
	/* Libc heap current position */
	unsigned long heap_current;
	/* Libc current heap residue size */
	unsigned long heap_residue;

	/* wait queue for process-wide waiters */
	struct waitqueue wq;

	struct signal_proc sigp;
};

/* process wait_state bits */
#define PROC_WAIT_WAITABLE  (1U << 0) /* set for posix_spawn() children */
#define PROC_WAIT_EXITED    (1U << 1) /* set when the last thread is gone */
#define PROC_WAIT_REAPED    (1U << 2) /* consumed by waitpid() */

/*
 * process resource cleanup
 * callback installation
 */
typedef void (*cleanup_func_t) (struct process *);
/*
 * cleanup macros, priority is down-decreased
 */
#define DECLARE_CLEANUP_HIGH(fn) \
	static __section(".cleanup.high") \
	__used cleanup_func_t _cleanup_high_##fn = fn
#define DECLARE_CLEANUP(fn) \
	static __section(".cleanup.medium") \
	__used cleanup_func_t _cleanup_##fn = fn
#define DECLARE_CLEANUP_LOW(fn) \
	static __section(".cleanup.low") \
	__used cleanup_func_t _cleanup_low_##fn = fn

#define PROCESS_ALIVE(p) (atomic_read(&(p)->alive) > 0)

extern struct spinlock __plock;
extern struct list_head __procs;

/*
 * Get the process, increase the reference counter.
 */
struct process *process_get(pid_t tidorpid);

/*
 * Put the process, if last thread exits, then kill the process.
 */
void process_put(struct process *proc);

/*
 * Get the process, increase the reference counter.
 * return the process structure
 * Only used on the SINGLE_INSTANCE
 */
struct process *__process_get(struct process_config *c);

/*
 * Put the process, if last thread exits, then kill the process.
 */
#define __process_put process_put


#if defined(CONFIG_USER)
/*
 * Create one userspace process by name
 * return the Process ID
 */
int process_create(const char *name, char * const *argv);
/*
 * Create and run one userspace process by name
 * return the Process ID
 */
int process_run(const char *name, char * const *argv);
/*
 * Create one userspace process by config
 * return the Process ID
 */
int __process_create(struct process_config *c, char * const *argv);

/*
 * Cleanup a just created process. (never run)
 */
void process_destroy(struct process *proc);

#else
static inline int process_create(const char *name, char * const *argv)
{ return -ENOTSUP; }
static inline int process_run(const char *name, char * const *argv)
{ return -ENOTSUP; }
static inline int __process_create(struct process_config *c, char * const *argv)
{ return -ENOTSUP; }
static inline void process_destroy(struct process *proc) { }
#endif

#ifdef __cplusplus
}
#endif

#endif
