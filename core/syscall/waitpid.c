// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * Minimal waitpid() syscall.
 *
 * Semantics (minimal):
 * - Supports waiting for a specific child pid (pid > 0).
 * - Supports waiting for any child (pid == -1).
 * - options supports WNOHANG only.
 * - status (if non-NULL) receives the child's raw _exit() value.
 * - Only processes created via posix_spawn() are waitable (PROC_WAIT_WAITABLE).
 */

#include <errno.h>
#include <stdbool.h>
#include <thread.h>
#include <process.h>
#include <wait.h>
#include <uaccess.h>
#include <waitpid.h>
#include <spinlock.h>
#include <list.h>
#include <syscall.h>

/*
 * Find any exited (or any) child from current process's children list.
 */
static struct process *waitpid_find_child_any(struct process *parent, bool exited_only)
{
	unsigned long flags = 0;
	struct process *child = NULL;
	struct process *ret = NULL;
	int state = 0;

	spin_lock_irqsave(&__plock, flags);
	list_for_each_entry(child, &parent->children, sibling) {
		state = atomic_read(&child->wait_state);
		if ((state & PROC_WAIT_WAITABLE) == 0)
			continue;
		if (state & PROC_WAIT_REAPED)
			continue;
		if (exited_only && ((state & PROC_WAIT_EXITED) == 0))
			continue;
		child->refc++;
		ret = child;
		break;
	}
	spin_unlock_irqrestore(&__plock, flags);

	return ret;
}

/*
 * Check if current process has any waitable children.
 */
static bool waitpid_has_child_any(struct process *parent)
{
	unsigned long flags = 0;
	struct process *child = NULL;
	int state = 0;
	bool ret = false;

	spin_lock_irqsave(&__plock, flags);
	list_for_each_entry(child, &parent->children, sibling) {
		state = atomic_read(&child->wait_state);
		if ((state & PROC_WAIT_WAITABLE) == 0)
			continue;
		if (state & PROC_WAIT_REAPED)
			continue;
		ret = true;
		break;
	}
	spin_unlock_irqrestore(&__plock, flags);

	return ret;
}

pid_t kwaitpid(pid_t pid, int *kstatus, int options)
{
	struct process *parent = current->proc;
	struct process *child = NULL;
	int status = 0, expected = 0, state = 0;
	bool nohang = false;

	if (pid == 0 || pid < -1)
		return -EINVAL;

	nohang = ((options & WNOHANG) != 0);
	if (options != 0 && !nohang)
		return -ENOTSUP;

	if (pid == -1) {
		for (;;) {
			child = waitpid_find_child_any(parent, true);
			if (child)
				break;
			if (!waitpid_has_child_any(parent))
				return -ECHILD;
			if (nohang)
				return 0;
			if (wait_interruptible(&parent->wq) == -EINTR)
				return -EINTR;
		}
		status = child->exit_code;
		pid = child->id;
		goto reap;
	}

	child = process_get(pid);
	if (!child)
		return -ECHILD;

	if (child->parent_id != parent->id) {
		process_put(child);
		return -ECHILD;
	}

	state = atomic_read(&child->wait_state);
	if ((state & PROC_WAIT_WAITABLE) == 0) {
		process_put(child);
		return -ECHILD;
	}

	if ((state & PROC_WAIT_EXITED) == 0) {
		if (nohang) {
			process_put(child);
			return 0;
		}
		/* Block until the child is fully gone (last thread removed). */
		if (wait_event_interruptible(&child->wq,
			atomic_read(&child->wait_state) & PROC_WAIT_EXITED) == -EINTR) {
			process_put(child);
			return -EINTR;
		}
	}

	status = child->exit_code;

reap:
	/* Consume (reap) only once. */
	for (;;) {
		expected = atomic_read(&child->wait_state);
		if (expected & PROC_WAIT_REAPED) {
			process_put(child);
			return -ECHILD;
		}
		if (atomic_compare_set(&child->wait_state, &expected,
			expected | PROC_WAIT_REAPED))
			break;
	}

	if (kstatus)
		*kstatus = status;

	/*
	 * Drop: (1) our process_get() ref, and (2) the extra ref retained by spawn
	 * to keep the child waitable (zombie-style).
	 */
	process_put(child);
	process_put(child);

	return pid;
}

long syscall_waitpid(struct thread_ctx *regs)
{
	pid_t pid = regs->r[ARG_REG + 1];
	int *ustatus = (int *)regs->r[ARG_REG + 2];
	int options = regs->r[ARG_REG + 3];
	int status = 0;
	pid_t r;
	bool nohang = false;

	if ((long)ustatus & (sizeof(int) - 1))
		return -EFAULT;

	if (pid == 0 || pid < -1)
		return -EINVAL;

	nohang = ((options & WNOHANG) != 0);
	if (options != 0 && !nohang)
		return -ENOTSUP;

	if (ustatus && !access_ok(ustatus, sizeof(*ustatus)))
		return -EFAULT;

	r = kwaitpid(pid, &status, options);
	if (r < 0)
		return r;

	if (ustatus) {
		if (copy_to_user(ustatus, &status, sizeof(status)))
			return -EFAULT;
	}

	return r;
}
