// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Userspace Process
 */

#include <errno.h>
#include <string.h>
#include <percpu.h>
#include <sched.h>
#include <mem.h>
#include <prng.h>
#include <list.h>
#include <device.h>
#include <kmalloc.h>
#include <atomic.h>
#include <vma.h>
#include <sbrk.h>
#include <file.h>
#include <trace.h>
#include <timer.h>
#include <page.h>
#include <uaccess.h>
#include <strmisc.h>

#include <__pthread.h>
#include <sys/pthread.h>
#include <ksignal.h>
#include <elf_proc.h>

SPIN_LOCK(__plock);
LIST_HEAD(__procs);

static void process_cleanup_run(struct process *p)
{
	cleanup_func_t func = NULL;
	unsigned long ptr = 0;
	unsigned long start = __cleanup_start();
	unsigned long end = __cleanup_end();

	for (ptr = start; ptr < end; ptr += sizeof(ptr)) {
		func = *(cleanup_func_t *)ptr;
		if (func)
			func(p);
	}
}

static int process_argv_info(char * const *argv,
	unsigned long *arglens, int *argc)
{
	int i = 0, ret = -1, cnt = 0;

	if (user_addr(argv)) {
		if (!access_ok(argv, sizeof(char *)))
			return -EFAULT;

		while ((i < MAX_ARGV_NUM) && argv[i]) {
			ret = strnlen_user(argv[i], MAX_ARGSTR_SIZE);
			if (ret < 0)
				return ret;

			cnt += ret;
			arglens[i++] = ret;

			if (((uintptr_t)&argv[i] & ~PAGE_MASK) == 0 &&
				!access_ok(&argv[i], sizeof(char *)))
				return -EFAULT;
		}
	} else {
		while ((i < MAX_ARGV_NUM) && argv[i]) {
			ret = strnlen(argv[i], MAX_ARGSTR_SIZE);
			cnt += ret;
			arglens[i++] = ret;
		}
	}

	*argc = i;

	return cnt;
}

static void process_free_argv(struct process *proc)
{
	int i = 0;
	void *uva = NULL;
	struct argv *m = proc->argv;
	char **pgs = NULL;

	proc->argv = NULL;

	if (m) {
		pgs = m->pages;
		uva = m->uva;
		while (pgs[i]) {
			pages_free_continuous(pgs[i]);
			unmap(proc->pt, uva + (PAGE_SIZE * i), PAGE_SIZE);
			i++;
		}
		vma_free(proc->vm, uva);
		kfree(m);
	}
}

static int process_alloc_argv(struct process *proc,
	char * const *argv)
{
	int argc = 0, ret = -1;
	char *_argv[2] = {proc->c->name, NULL};
	int off = 0, pos = 0, orilen = 0, first = true;
	int nrbytes = 0, i = 0, len = 0, argvsize = 0;
	char **uptr = NULL, **kptr = NULL;
	char *dst = NULL;
	const char *arg = NULL;
	struct argv *m = NULL;
	void *uva = NULL;
	unsigned long *arglens = NULL;
	int kmgrsize = 0;

	if (!argv || !argv[0])
		argv = _argv;

	dst = pages_alloc_continuous(PG_RW | PG_ZERO, 1);
	if (!dst)
		return -ENOMEM;

	/* calc the total strlen of all argv */
	arglens = (unsigned long *)dst;
	ret = process_argv_info(argv, arglens, &argc);
	if (ret < 0) {
		pages_free_continuous(dst);
		return ret;
	}
	/* user-space argv pointers */
	argvsize = (argc + 1) * sizeof(char *);

	/* total space needed */
	ret = ret + argc + argvsize;

	if ((argc == MAX_ARGV_NUM) || (ret > MAX_ARGV_SIZE)) {
		pages_free_continuous(dst);
		return -E2BIG;
	}

	/* kernel-space argv page pointers */
	kmgrsize = ret >> PAGE_SHIFT;
	kmgrsize = (kmgrsize + 2) * sizeof(char *);

	m = kzalloc(sizeof(*m) + kmgrsize);
	if (!m) {
		pages_free_continuous(dst);
		return -ENOMEM;
	}

	uva = vma_alloc(proc->vm, MAX_ARGV_SIZE);
	if (!uva) {
		kfree(m);
		pages_free_continuous(dst);
		return -ENOMEM;
	}

	m->argc = argc;
	m->uva = uva;
	kptr = m->pages;

	proc->argv = m;

	for (i = 0; i < argc; i++) {
		off = 0;
		arg = argv[i];
		orilen = len = arglens[i] + 1;

		while (len > 0) {
			if (first) {
				ret = map(proc->pt, virt_to_phys(dst),
						uva, PAGE_SIZE, PG_RW);
				if (ret != 0) {
					pages_free_continuous(dst);
					goto err;
				}
				uptr = (void *)dst;
				uptr[argc] = NULL;
				kptr[0] = dst;
				dst += argvsize;
				pos += argvsize;
				first = false;
			}

			/* next page ? */
			if ((pos & ~PAGE_MASK) == 0) {
				dst = pages_alloc_continuous(PG_RW | PG_ZERO, 1);
				if (!dst) {
					ret = -ENOMEM;
					goto err;
				}
				ret = map(proc->pt, virt_to_phys(dst),
						uva + pos, PAGE_SIZE, PG_RW);
				if (ret != 0) {
					pages_free_continuous(dst);
					goto err;
				}
				kptr[pos >> PAGE_SHIFT] = dst;
			}

			nrbytes = min(len, (int)(PAGE_SIZE - (pos & ~PAGE_MASK)));
			if (user_addr(argv)) {
				if (copy_from_user(dst, arg + off, nrbytes)) {
					ret = -EFAULT;
					goto err;
				}
			} else {
				memcpy(dst, arg + off, nrbytes);
			}

			if (len == orilen)
				uptr[i] = uva + pos;

			dst += nrbytes;
			off += nrbytes;
			len -= nrbytes;
			pos += nrbytes;
		}
	}

	return 0;

err:
	process_free_argv(proc);
	return ret;
}

static void process_orphan_children(struct process *proc)
{
	unsigned long flags = 0;
	struct process *child = NULL, *tmp = NULL;

	spin_lock_irqsave(&__plock, flags);

	list_for_each_entry_safe(child, tmp, &proc->children, sibling) {
		list_del(&child->sibling);
		child->parent_id = 0;
	}

	spin_unlock_irqrestore(&__plock, flags);
}

static void __process_destroy(struct process *proc)
{
	/* set alive to negative */
	atomic_set(&proc->alive, -(INT_MAX >> 1));

	process_free_argv(proc);

	sigp_free(proc);

	elf_unload_proc(proc);

	process_cleanup_run(proc);

	vma_destroy(proc->vm);
	vma_destroy(proc->vm4ree);

	free_pt(proc->pt);

	waitqueue_flush(&proc->wq);

	assert(list_empty(&proc->heap_pages));
	assert(list_empty(&proc->threads));
	assert(list_empty(&proc->utimers));
	assert(list_empty(&proc->mmaps));

	mutex_destroy(&proc->mlock);

	/*
	 * Before releasing the PID, orphan all children to prevent
	 * PID-reuse from causing a new process (with same PID) to
	 * inherit these children.
	 */
	process_orphan_children(proc);

	sched_free_id(proc->id);
	kfree(proc);
}

/*
 * Get the process by config, increase the reference counter.
 * return the process structure
 * Only used on the SINGLE_INSTANCE
 */
struct process *__process_get(struct process_config *c)
{
	unsigned long flags = 0;
	struct process *proc = NULL, *ret = NULL;

	if (!c || (!c->single_instance))
		return NULL;

	spin_lock_irqsave(&__plock, flags);
	list_for_each_entry(proc, &__procs, node) {
		if ((proc->c == c) && PROCESS_ALIVE(proc)) {
			proc->refc++;
			ret = proc;
			break;
		}
	}
	spin_unlock_irqrestore(&__plock, flags);
	return ret;
}

/*
 * Find process by ID without acquiring __plock (caller must hold it).
 * Does NOT increment reference counter.
 */
static struct process *process_get_locked(pid_t id)
{
	struct process *proc = NULL;

	if (id <= 0)
		return NULL;

	list_for_each_entry(proc, &__procs, node) {
		if (proc->id == id)
			return proc;
	}
	return NULL;
}

/*
 * Get the process by ID (tid or pid)
 * increase the reference counter.
 * return the process structure
 */
struct process *process_get(pid_t id)
{
	struct thread *t = NULL;
	struct process *proc = NULL, *ret = NULL;
	unsigned long flags = 0;

	if (id <= 0)
		return NULL;

	spin_lock_irqsave(&__plock, flags);

	t = thread_get(id);
	if (t) {
		proc = t->proc;
		proc->refc++;
		ret = proc;
		thread_put(t);
	} else {
		list_for_each_entry(proc, &__procs, node) {
			if (proc->id == id) {
				proc->refc++;
				ret = proc;
				break;
			}
		}
	}

	spin_unlock_irqrestore(&__plock, flags);
	return ret;
}

/*
 * Put the process, if last thread exits,
 * then kill the process.
 */
void process_put(struct process *proc)
{
	unsigned long flags = 0;

	if (!proc)
		return;

	spin_lock_irqsave(&__plock, flags);
	assert(proc->refc > 0);
	if (--proc->refc == 0) {
		list_del(&proc->node);
		/* Remove from parent's children list if still linked */
		list_del(&proc->sibling);
		spin_unlock_irqrestore(&__plock, flags);
		__process_destroy(proc);
	} else {
		spin_unlock_irqrestore(&__plock, flags);
	}
}

/*
 * Cleanup a just created process. (which never run)
 */
void process_destroy(struct process *proc)
{
	struct thread *t = thread_get(proc->id);

	if (t) {
		thread_put(t);
		pthread_destroy(t);
	}
	assert(proc->refc == 1);
	process_put(proc);
}

/*
 * Add to global list and link to parent's children list
 */
static inline void process_add(struct process *proc)
{
	unsigned long flags = 0;
	struct process *parent = NULL;

	spin_lock_irqsave(&__plock, flags);
	list_add_tail(&proc->node, &__procs);
	/* Link to parent's children list */
	if (proc->parent_id > 0) {
		parent = process_get_locked(proc->parent_id);
		if (parent)
			list_add_tail(&proc->sibling, &parent->children);
	}
	spin_unlock_irqrestore(&__plock, flags);
}

static int process_ipc_security_check(struct process_config *c)
{
	struct process *proc = current->proc;

	if (proc->c->privilege)
		return 0;

	/*
	 * check if current process has permission
	 * to access the target process
	 */
	if (!strstr_token(proc->c->ipc_acl, c->name, ',')) {
		EMSG("ipc_acl: %s target: %s\n", proc->c->ipc_acl, c->name);
		return -EACCES;
	}

	return 0;
}

int __process_create(struct process_config *c, char * const *argv)
{
	int ret = -1, id = -1;
	struct process *proc = NULL;
	DECLARE_DETACHED_PTHREAD_ATTR(attr);

	if (!c)
		return -ENOENT;

	/* memory check */
	if (nr_continuous_free_pages() < 16)
		return -ENOMEM;

	/* single-instance check */
	proc = __process_get(c);
	if (proc) {
		__process_put(proc);
		return -EEXIST;
	}

	if (process_ipc_security_check(c) != 0)
		return -EACCES;

	proc = kzalloc(sizeof(struct process));
	if (!proc)
		return -ENOMEM;

	proc->c = c;
	INIT_LIST_HEAD(&proc->threads);
	INIT_LIST_HEAD(&proc->mmaps);
	INIT_LIST_HEAD(&proc->utimers);
	INIT_LIST_HEAD(&proc->children);
	INIT_LIST_HEAD(&proc->sibling);
	waitqueue_init(&proc->wq);
	spin_lock_init(&proc->slock);
	mutex_init(&proc->mlock);

	proc->refc = 1;
	proc->parent_id = current->proc->id;
	atomic_set(&proc->wait_state, 0);
	proc->exit_code = 0;

#if defined(CONFIG_ASLR)
	prng(&proc->aslr, sizeof(proc->aslr));
	proc->aslr = rounddown(proc->aslr % USER_ASLR_SIZE, PAGE_SIZE);
#endif

	ret = sigp_init(proc);
	if (ret != 0)
		goto out;

	ret = sbrk_init(proc);
	if (ret != 0)
		goto out;

	/*
	 * allocate the page table (translation table base)
	 */
	ret = alloc_pt(proc);
	if (ret != 0)
		goto out;

	if (IS_ENABLED(CONFIG_REE)) {
		proc->vm4ree = vma_create(USER_VM4REE_VA(proc), USER_VM4REE_SIZE, PAGE_SIZE);
		if (!proc->vm4ree) {
			ret = -ENOMEM;
			goto out;
		}
	}
	proc->vm = vma_create(USER_VM4TEE_VA(proc), USER_VM4TEE_SIZE, PAGE_SIZE);
	if (!proc->vm) {
		ret = -ENOMEM;
		goto out;
	}

	ret = process_alloc_argv(proc, argv);
	if (ret != 0)
		goto out;

	/*
	 * 1. load the Process elf from filesystem
	 * 2. allocate the page table (translation table base)
	 * 3. map the libc/process's elf to Process(TA) userspace
	 */
	ret = elf_load_proc(proc);
	if (ret != 0) {
		EMSG("load %s - %s failed %d\n", proc->c->name,
			proc->c->path, ret);
		goto out;
	}

	/* assign the pthread stacksize definied in the certificate */
	attr.stacksize = proc->c->ustack_size;
	id = pthread_kcreate(proc, &attr,
		(thread_func_t)proc->main_func, proc->argv->uva);
	if (id > 0) {
		process_add(proc);
		return id;
	}

	ret = id;

out:
	__process_destroy(proc);
	return ret;
}

int process_create(const char *name, char * const *argv)
{
	return __process_create(process_config_of(name), argv);
}

int process_run(const char *name, char * const *argv)
{
	pid_t id = -1;

	id = __process_create(process_config_of(name), argv);

	if (id > 0)
		sched_ready(id);

	return id;
}
