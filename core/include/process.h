/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Process structures
 */

#ifndef _PROCESS_H
#define _PROCESS_H

#include <ida.h>
#include <mem.h>
#include <page.h>
#include <file.h>
#include <sched.h>
#include <mutex.h>
#include <kproc.h>
#include <ksignal.h>

#include <process_config.h>

#define MAX_ARGV_NUM (256)
#define MAX_ARGV_SIZE (1024 * 1024)
#define MAX_ARGSTR_SIZE (256 * 1024)

#define PROCESS_ENTRY_LEN (64)

/* 32 ~ 8192 */
#define PROCESS_THREAD_MAX (sched_idx_max)

/* 256 FD per MB */
#define PROCESS_FD_MAX (mem_size >> 12)

struct argv  {
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
	/* list of its threads (include exiting thread) */
	struct list_head threads;

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

	/* __proc_self user va */
	struct __process *pself_uva;
	/* __proc_self kernel va */
	struct __process *pself;
	/* __proc_self page */
	struct page *pself_page;

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

/*
 * process resource cleanup
 * callback installation
 */
typedef void (*cleanup_func_t) (struct process *);
/*
 * cleanup macros, priority is down-decreased
 */
#define DECLARE_CLEANUP_HIGH(fn) \
	static  __section(".cleanup.high") \
	__used cleanup_func_t _cleanup_high##fn = fn
#define DECLARE_CLEANUP(fn) \
	static  __section(".cleanup.medium") \
	__used cleanup_func_t _cleanup_##fn = fn
#define DECLARE_CLEANUP_LOW(fn) \
	static  __section(".cleanup.low") \
	__used cleanup_func_t _cleanup_low##fn = fn

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

/*
 * Create one userspace process
 * return the Process ID
 */
int process_create(const TEE_UUID *uuid);

/*
 * Create and run one userspace process with "argv"
 * return the Process ID
 */
#ifdef CONFIG_USER
int process_run(const char *name, char * const *argv);
#else
static inline int process_run(const char *name, char * const *argv)
{ return -ENOTSUP; }
#endif

#endif
