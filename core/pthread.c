// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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
		if (t->ustack_uva == NULL)
			return ret;

		t->ustack_pages = pages_sc_alloc(nr_pages);
		if (t->ustack_pages == NULL)
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
	if (ret) {
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

	self->proc = t->proc->pself_uva;

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
	unsigned long flags = 0;
	struct timespec tm, *rt = &proc->runtime;

	spin_lock_irqsave(&proc->slock, flags);
	list_del(&t->node);
	/* record the exiting thread's cputime */
	__sched_thread_cputime(t, &tm);
	timespecadd(&tm, rt, rt);
	spin_unlock_irqrestore(&proc->slock, flags);
}

/*
 * Cleanup the mutex
 */
static void pthread_cleanup_mutexes(struct thread *t)
{
	struct mutex *m = NULL, *n = NULL;

	list_for_each_entry_safe(m, n, &t->mutexs, node) {
		IMSG("cleanup mutex: %s\n", t->name);
		mutex_unlock(m);
	}
}

static void pthread_cleanup_wqnodes(struct thread *t)
{
	struct waitqueue_node *n = NULL, *_n = NULL;

	list_for_each_entry_safe(n, _n, &t->wqnodes, tnode) {
		LMSG("%s waiting @ %s() line %d p=%p\n",
			t->name, n->fnname, n->linenr, n->priv);
		waitqueue_node_del(n);
	}
}

/*
 * Cleanup the exited thread
 */
static void pthread_destroy(struct work *w)
{
	if (w) {
		struct thread *t = container_of(w,
				struct thread, destroy);
		struct process *proc = t->proc;

		pthread_del(t);

		pthread_cleanup_mutexes(t);
		pthread_cleanup_wqnodes(t);

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
		if (attr->stackaddr && !attr->stacksize)
			return -EINVAL;

		p->detachstate = attr->detachstate;
		p->inherit = attr->inheritsched;

		p->policy = attr->schedpolicy;
		p->scope = attr->contentionscope;
		p->priority = attr->schedparam.sched_priority;

		if (attr->stackaddr)
			p->stackaddr = attr->stackaddr;

		if (attr->stacksize)
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
	int ret = -1, pput = false, tid = -1;
	int kstack_size = PAGE_SIZE * (sizeof(long)/sizeof(int));

	if (proc == NULL)
		return -EINVAL;

	/* roughly check: proc may be exiting */
	if (!PROCESS_ALIVE(proc) && proc->id)
		return -EINTR;

	/* roughly check: below than PROCESS_THREAD_MAX */
	if (atomic_read(&proc->alive) >= PROCESS_THREAD_MAX)
		return -EAGAIN;

	t = thread_alloc(kstack_size);
	if (t == NULL)
		return -ENOMEM;

	/*
	 * init the basic thread info
	 */
	t->proc = proc;
	INIT_LIST_HEAD(&t->mutexs);
	INIT_LIST_HEAD(&t->wqnodes);
	waitqueue_init(&t->wait_q);
	waitqueue_init(&t->join_q);
	mutex_init(&t->mlock);
	INIT_WORK(&t->destroy, pthread_destroy);

	ret = sigt_init(t);
	if (ret)
		goto error;

	/* increase the process reference counter */
	if (proc->id) {
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
	if (ret)
		goto error;

	/*
	 * Initialize the __pthread_ attr
	 */
	ret = pthread_attr_kinit(t, attr);
	if (ret)
		goto error;

	/*
	 * check and allocate the user-mode stack
	 */
	ret = pthread_alloc_usp(t, t->tuser->stackaddr,
			t->tuser->stacksize);
	if (ret)
		goto error;

	/*
	 * install the scheduler on this thread
	 */
	ret = sched_install(t, t->tuser->policy,
			t->tuser->priority);
	if (ret)
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
		sched_entry_init(tid,
			proc->pself->wrapper.pthread_entry,
			func, data);
	} else {
		sched_entry_init(tid,
			proc->pself->wrapper.proc_entry,
			func, data);
	}

	/* final step */
	ret = pthread_add(t);

error:
	if (ret != 0) {
		if (proc->id == tid)
			proc->id = 0;
		sched_uninstall(t->sched);
		pthread_free_usp(t);
		pthread_free_tuser(t);
		thread_free(t);
		if (pput)
			process_put(proc);
		return ret;
	}

	return tid;
}
