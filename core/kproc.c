// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * for the-one Kernel Process
 */

#include <errno.h>
#include <string.h>
#include <mmu.h>
#include <list.h>
#include <init.h>
#include <atomic.h>
#include <trace.h>
#include <timer.h>
#include <thread.h>
#include <process.h>

#include <kproc.h>

static struct process_config __kc = {0};
static struct process __kproc = {0};
static struct pt_struct __kpt = {0};
static struct thread __kthread = {0};

/*
 * Returns the kernel dummy thread pointer
 */
struct thread *kthread(void)
{
	return &__kthread;
}

/*
 * Returns the kernel process pointer
 */
struct process *kproc(void)
{
	return &__kproc;
}

/*
 * returns the kernel page table pointer
 */
struct pt_struct *kpt(void)
{
	return &__kpt;
}

/*
 * kernel process init
 *
 * one SoC have only one kernel process
 * and multiple user-processes
 */
int __init kproc_init(void)
{
	struct process *proc = kproc();
	struct thread *t = kthread();
	struct pt_struct *pt = kpt();

	t->proc = proc;
	strlcpy(t->name, "kernel", THREAD_NAME_LEN);

	INIT_LIST_HEAD(&t->mutexs);
	INIT_LIST_HEAD(&t->wqnodes);
	INIT_LIST_HEAD(&proc->threads);
	waitqueue_init(&proc->wq);
	spin_lock_init(&proc->slock);

#if defined(CONFIG_MMU)
	mmu_init_kpt(pt);
#endif

	proc->pt = pt;
	proc->c = &__kc;
	proc->refc = INT_MAX >> 1;
	atomic_set(&proc->alive, 1);
	proc->c->privilege = true;
	strlcpy(proc->c->name, "kernel", PROCESS_NAME_LEN);

	return 0;
}

static void __init kproc_stdfd_init(void)
{
#if defined(CONFIG_UART)
	int fd = sys_open("/dev/uart0", O_RDWR);
#else
	int fd = sys_open("/dev/null", O_RDWR);
#endif

	assert(fd >= 0);

	sys_dup2(fd, STDIN_FILENO);
	sys_dup2(fd, STDOUT_FILENO);
	sys_dup2(fd, STDERR_FILENO);

	if (fd > STDERR_FILENO)
		sys_close(fd);
}
MODULE_INIT_ARCH(kproc_stdfd_init);
