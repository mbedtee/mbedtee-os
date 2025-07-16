// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * POSIX thread stubs in Kernel
 */

#include <mem.h>
#include <vma.h>
#include <percpu.h>
#include <trace.h>
#include <sched.h>
#include <errno.h>
#include <list.h>
#include <timer.h>
#include <kmalloc.h>
#include <string.h>
#include <sleep.h>
#include <ida.h>

#include <page_scatter.h>

#include <__pthread.h>
#include <sys/pthread.h>
#include <sys/poll.h>
#include <file.h>

/*
 * allocate/map the thread's user-stack
 */
extern int pthread_alloc_usp(struct thread *t,
	void *addr, size_t size)
{
	int ret = -ENOMEM;
	size_t nr_pages = 0;

	if (!addr) {
		t->ustack_size = roundup(size, PAGE_SIZE);
		nr_pages = t->ustack_size >> PAGE_SHIFT;

		t->ustack_uva = vma_alloc(t->proc->vm, t->ustack_size);
		if (!t->ustack_uva)
			return ret;

		t->ustack_pages = pages_sc_alloc(nr_pages);
		if (!t->ustack_pages)
			goto out;

		ret = pages_sc_map(t->ustack_pages, t->proc->pt,
				t->ustack_uva, nr_pages, PG_RW | PG_ZERO);
		if (ret != 0) {
			pages_sc_free(t->ustack_pages, nr_pages);
			goto out;
		}
	} else {
		t->ustack_uva = addr;
		t->ustack_size = size;
	}

	return 0;

out:
	vma_free(t->proc->vm, t->ustack_uva);
	t->ustack_uva = NULL;
	t->ustack_pages = NULL;
	return ret;
}

/*
 * unmap/free the thread's user-stack
 */
static void pthread_free_usp(struct thread *t)
{
	/*
	 * only free the stack allocated by the kernelspace.
	 * user application managed stack memory shall be
	 * handled by the application
	 */
	if (!t->ustack_pages)
		return;

	pages_sc_unmap(t->ustack_pages,
				t->proc->pt, t->ustack_uva,
				t->ustack_size >> PAGE_SHIFT);

	pages_sc_free(t->ustack_pages, t->ustack_size >> PAGE_SHIFT);

	vma_free(t->proc->vm, t->ustack_uva);

	t->ustack_pages = NULL;
	t->ustack_uva = NULL;
}

/*
 * allocate/map the __pthread struct for __pthread_self()
 */
static int pthread_alloc_tuser(struct thread *t)
{
	int ret = -ENOMEM;
	void *kva = NULL;
	void *uva = NULL;
	struct page *p = NULL;

	p = page_alloc();
	if (!p)
		return -ENOMEM;

	kva = page_address(p);

	uva = vma_alloc(t->proc->vm, PAGE_SIZE);
	if (!uva) {
		ret = -ENOMEM;
		goto out;
	}

	ret = page_map(p, t->proc->pt, uva, PG_RW | PG_ZERO);
	if (ret != 0) {
		vma_free(t->proc->vm, uva);
		goto out;
	}

	t->tuser_page = p;
	t->tuser_uva = uva;
	t->tuser = kva;

	return 0;

out:
	page_free(p);
	return ret;
}

/*
 * unmap/free the __pthread struct for __pthread_self()
 */
static void pthread_free_tuser(struct thread *t)
{
	if (!t || !t->tuser)
		return;

	page_unmap(t->tuser_page, t->proc->pt, t->tuser_uva);
	vma_free(t->proc->vm, t->tuser_uva);
	page_free(t->tuser_page);

	t->tuser = NULL;
}

/*
 * initialize the kern part of the
 * __pthread struct for __pthread_self()
 */
static void pthread_init_tuser(struct thread *t)
{
	struct __pthread *self = t->tuser;

	self->id = t->id;
	self->idmax = sched_idx_max;

	/*
	 * (pid << 16) | tid
	 */
	self->pthread = t->proc->id << (BITS_PER_INT / 2);
	self->pthread |= t->id;
}

/*
 * add to process's thread list
 */
static int pthread_add(struct thread *t)
{
	int ret = 0;
	unsigned long flags = 0;
	struct process *proc = t->proc;

	spin_lock_irqsave(&proc->slock, flags);
	if (PROCESS_ALIVE(proc))
		list_add_tail(&t->node, &proc->threads);
	else
		ret = -EINTR;
	spin_unlock_irqrestore(&proc->slock, flags);

	return ret;
}

/*
 * del from process's thread list
 */
static void pthread_del(struct thread *t)
{
	struct process *proc = t->proc;
	struct process *parent = NULL;
	unsigned long flags = 0;
	struct timespec tm, *rt = &proc->runtime;
	pid_t parent_id = 0;
	bool notify_parent = false;
	bool last_thread = false;

	spin_lock_irqsave(&proc->slock, flags);
	list_del(&t->node);
	/* record the exiting thread's cputime */
	__sched_thread_cputime(t, &tm);
	timespecadd(&tm, rt, rt);
	/*
	 * Capture the first non-zero thread retval as exit_code.
	 * This handles pthread_exit(err) when _exit() was never called.
	 */
	if (proc->exit_code == 0)
		proc->exit_code = t->join_q.notification;
	if (list_empty(&proc->threads) &&
		!(atomic_read(&proc->wait_state) & PROC_WAIT_EXITED)) {
		atomic_orr(&proc->wait_state, PROC_WAIT_EXITED);
		wakeup_notify(&proc->wq, proc->exit_code);
		parent_id = proc->parent_id;
		notify_parent = ((atomic_read(&proc->wait_state) \
				& PROC_WAIT_WAITABLE) != 0);
		last_thread = true;
	}
	spin_unlock_irqrestore(&proc->slock, flags);

	if (last_thread)
		fdesc_close_all(proc);

	if (notify_parent && parent_id > 0) {
		parent = process_get(parent_id);
		if (parent) {
			wakeup_notify(&parent->wq, 1);
			process_put(parent);
		}
	}
}

/*
 * Cleanup the exited thread
 */
static void pthread_destroy_work(struct work *w)
{
	if (w) {
		struct thread *t = container_of(w,
				struct thread, destroy);
		struct process *proc = t->proc;

		pthread_del(t);

		thread_cleanup_run(t);

		wakeup(&t->join_q);

		waitqueue_flush(&t->join_q);

		pthread_free_usp(t);
		pthread_free_tuser(t);

		sigt_free(t);

		/*
		 * PID (process ID) is the process resource
		 * so it shall only be freed in the process destroy routine
		 */
		if (t->id != proc->id)
			sched_free_id(t->id);

		kfree(t->brstack);

		thread_free(t);

		process_put(proc);
	}
}

/*
 * Cleanup the just created thread (which never run)
 */
void pthread_destroy(struct thread *t)
{
	struct process *proc = t->proc;
	unsigned long flags = 0;

	spin_lock_irqsave(&proc->slock, flags);
	list_del(&t->node);
	spin_unlock_irqrestore(&proc->slock, flags);

	sched_uninstall(t->sched);
	pthread_free_usp(t);
	pthread_free_tuser(t);
	sigt_free(t);
	thread_free(t);
}

static int pthread_attr_kinit(struct thread *t,
	const pthread_attr_t *attr)
{
	struct __pthread *p = t->tuser;
	DECLARE_DEFAULT_PTHREAD(dp);

	memcpy(p, &dp, sizeof(*p));

	if (attr) {
		if (!attr->is_initialized)
			return -EINVAL;
		if (attr->schedpolicy != SCHED_OTHER &&
			attr->schedpolicy != SCHED_RR)
			return -EINVAL;
		if ((attr->schedparam.sched_priority > SCHED_PRIO_USER_MAX) ||
			(attr->schedparam.sched_priority < SCHED_PRIO_USER_MIN))
			return -EINVAL;
		if (attr->contentionscope != PTHREAD_SCOPE_SYSTEM)
			return -EINVAL;
		if (attr->inheritsched != PTHREAD_EXPLICIT_SCHED &&
			attr->inheritsched != PTHREAD_INHERIT_SCHED)
			return -EINVAL;
		if (attr->stackaddr && attr->stacksize == 0)
			return -EINVAL;

		p->detachstate = attr->detachstate;
		p->inherit = attr->inheritsched;

		p->policy = attr->schedpolicy;
		p->scope = attr->contentionscope;
		p->priority = attr->schedparam.sched_priority;

		if (attr->stackaddr)
			p->stackaddr = attr->stackaddr;

		if (attr->stacksize != 0)
			p->stacksize = attr->stacksize;
	}

	if (p->stacksize < t->proc->c->ustack_size)
		p->stacksize = t->proc->c->ustack_size;

	return 0;
}

/*
 * Create the userspace pthread
 * return the thread ID
 */
int pthread_kcreate(struct process *proc,
	pthread_attr_t *attr, pthread_func_t func, void *data)
{
	struct thread *t = NULL;
	int ret = -1, tid = -1;
	bool pput = false;
	int kstack_size = PAGE_SIZE * (sizeof(long)/sizeof(int));

	if (!proc)
		return -EINVAL;

	/* roughly check: proc may be exiting */
	if (!PROCESS_ALIVE(proc) && proc->id != 0)
		return -EINTR;

	/* roughly check: below than PROCESS_THREAD_MAX */
	if (atomic_read(&proc->alive) >= PROCESS_THREAD_MAX)
		return -EAGAIN;

	t = thread_alloc(kstack_size);
	if (!t)
		return -ENOMEM;

	/*
	 * init the basic thread info
	 */
	t->proc = proc;
	INIT_LIST_HEAD(&t->node);
	INIT_LIST_HEAD(&t->mutexs);
	INIT_LIST_HEAD(&t->wqnodes);
	INIT_LIST_HEAD(&t->polls);
	waitqueue_init(&t->wait_q);
	waitqueue_init(&t->join_q);
	mutex_init(&t->mlock);
	INIT_WORK(&t->destroy, pthread_destroy_work);

	ret = sigt_init(t);
	if (ret != 0)
		goto error;

	/*
	 * Inherit the parent thread's signal mask (POSIX: pthread_create
	 * inherits the caller's signal mask).
	 */
	t->sigt.mask = current->sigt.mask;

	/* increase the process reference counter */
	if (proc->id != 0) {
		if (!process_get(proc->id)) {
			ret = -ESRCH; /* proc may be exiting */
			goto error;
		}
		pput = true;
	}

	/*
	 * allocate/map the __pthread struct for __pthread_self()
	 */
	ret = pthread_alloc_tuser(t);
	if (ret != 0)
		goto error;

	/*
	 * Initialize the __pthread_ attr
	 */
	ret = pthread_attr_kinit(t, attr);
	if (ret != 0)
		goto error;

	/*
	 * check and allocate the user-mode stack
	 */
	ret = pthread_alloc_usp(t, t->tuser->stackaddr,
			t->tuser->stacksize);
	if (ret != 0)
		goto error;

	/*
	 * install the scheduler on this thread
	 */
	ret = sched_install(t, t->tuser->policy,
			t->tuser->priority);
	if (ret != 0)
		goto error;

	tid = t->id;
	/*
	 * Set the process_ID to the primary thread's ID
	 */
	if (proc->id == 0)
		proc->id = tid;

	snprintf(t->name, sizeof(t->name), "%s@%04d|%04d",
			proc->c->name, tid, proc->id);

	/*
	 * Initialize the __pthread_self()
	 */
	pthread_init_tuser(t);

	if (proc->id != tid) {
		ret = sched_entry_init(tid,
			proc->wrapper.pthread_entry,
			func, data);
	} else {
		ret = sched_entry_init(tid,
			proc->wrapper.proc_entry,
			func, data);
	}
	if (ret != 0)
		goto error;

	/* final step */
	ret = pthread_add(t);

error:
	if (ret != 0) {
		pthread_destroy(t);
		if (pput)
			process_put(proc);
		return ret;
	}

	return tid;
}
