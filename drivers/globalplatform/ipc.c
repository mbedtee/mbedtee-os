// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * IPC Call Implementation (GlobalPlatform Style TA<->TA)
 */

#include <stddef.h>
#include <trace.h>
#include <strmisc.h>
#include <percpu.h>
#include <cpu.h>
#include <percpu.h>
#include <thread.h>
#include <vma.h>
#include <ipc.h>
#include <errno.h>
#include <kmalloc.h>

#include <tee_api_types.h>
#include <tee_api_defines.h>

#include <sys/pthread.h>
#include <pthread_session.h>

static LIST_HEAD(ipc_shms);
static DECLARE_MUTEX(ipc_mutex);

struct ipc_shm {
	size_t cnt;
	off_t offset;
	struct page **pages;
	void *va;
	struct process *proc;
	struct list_head node;
};

static inline void ipc_shm_lock(void)
{
	mutex_lock(&ipc_mutex);
}

static inline void ipc_shm_unlock(void)
{
	mutex_unlock(&ipc_mutex);
}

static inline struct pthread_session *ipc_session(
	struct thread *t)
{
	BUILD_ERROR_ON(PTHREAD_SESSION_OFFSET +
		sizeof(struct pthread_session) > PAGE_SIZE);

	return ((struct pthread_session *)((long)(t->tuser)
			+ PTHREAD_SESSION_OFFSET));
}

static struct ipc_shm *ipc_shm_of(
	struct process *proc, void *va)
{
	struct ipc_shm *n = NULL, *ret = NULL;

	list_for_each_entry(n, &ipc_shms, node) {
		if ((n->proc == proc) &&
			(n->va + n->offset == va)) {
			ret = n;
			break;
		}
	}

	return ret;
}
static void *ipc_shm_map(struct process *proc,
	void *buffer, size_t size)
{
	void *shm_va = NULL;
	struct page **ppages = NULL;
	long nr_pages = 0, ret = -1, i = 0;
	off_t offset = (unsigned long)buffer & (~PAGE_MASK);
	unsigned long start = (unsigned long)buffer & PAGE_MASK;
	struct ipc_shm *shm = NULL;

	nr_pages = roundup(size + offset, PAGE_SIZE) >> PAGE_SHIFT;

	ppages = kcalloc(nr_pages, sizeof(*ppages));
	if (ppages == NULL)
		return ERR_PTR(-ENOMEM);

	ret = pin_user_pages(start, nr_pages, ppages);
	if (ret != nr_pages) {
		ret = -EFAULT;
		goto out;
	}

	shm_va = vma_alloc(proc->vm, nr_pages << PAGE_SHIFT);
	if (shm_va == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < nr_pages; i++) {
		ret = page_map(ppages[i], proc->pt,
				shm_va + (PAGE_SIZE * i), PG_RW);
		if (ret != 0)
			goto out;
	}

	shm = kmalloc(sizeof(*shm));
	if (shm == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	shm->va = shm_va;
	shm->offset = offset;
	shm->cnt = nr_pages;
	shm->proc = proc;
	shm->pages = ppages;

	ipc_shm_lock();
	list_add_tail(&shm->node, &ipc_shms);
	ipc_shm_unlock();

	return shm_va + offset;

out:
	while (--i >= 0)
		page_unmap(ppages[i], proc->pt, shm_va + (PAGE_SIZE * i));
	vma_free(proc->vm, shm_va);
	unpin_user_pages(ppages, nr_pages);
	kfree(ppages);
	return ERR_PTR(ret);
}

static int ipc_shm_unmap(struct process *proc, void *buffer)
{
	int cnt = 0;
	struct ipc_shm *shm = NULL;

	ipc_shm_lock();
	shm = ipc_shm_of(proc, buffer);
	if (shm == NULL) {
		ipc_shm_unlock();
		return -EINVAL;
	}

	list_del(&shm->node);
	ipc_shm_unlock();

	cnt = shm->cnt;
	while (--cnt >= 0)
		page_unmap(shm->pages[cnt], proc->pt, shm->va + (PAGE_SIZE * cnt));

	vma_free(proc->vm, shm->va);

	unpin_user_pages(shm->pages, shm->cnt);

	kfree(shm->pages);

	kfree(shm);

	return 0;
}

static void ipc_param_put(TEE_Param *params,
	uint32_t params_type, struct thread *t)
{
	int i = 0, type = 0;
	struct pthread_session *sess = ipc_session(t);

	for (i = 0; i < 4; i++) {
		type = TEE_PARAM_TYPE_GET(params_type, i);

		if ((type == TEE_PARAM_TYPE_VALUE_INOUT) ||
			(type == TEE_PARAM_TYPE_VALUE_OUTPUT)) {
			params[i].value.a = sess->params[i].value.a;
			params[i].value.b = sess->params[i].value.b;
		} else if ((type == TEE_PARAM_TYPE_MEMREF_INPUT) ||
			(type == TEE_PARAM_TYPE_MEMREF_INOUT) ||
			(type == TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
			ipc_shm_unmap(t->proc, sess->params[i].memref.buffer);
			if (type != TEE_PARAM_TYPE_MEMREF_INPUT)
				params[i].memref.size = sess->params[i].memref.size;
		}
	}
	sess->cancel_mask = true;
	sess->cancel_flag = false;
	sess->stat = SESS_DONE;
}

static int ipc_param_get(TEE_Param *params,
	uint32_t params_type, uint32_t cmd, struct thread *t)
{
	void *shm_va = 0;
	int i = 0, ret = -1, type = 0;
	struct pthread_session *sess = ipc_session(t);

	for (i = 0; i < 4; i++) {
		type = TEE_PARAM_TYPE_GET(params_type, i);

		switch (type) {
		case TEE_PARAM_TYPE_NONE:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
			sess->params[i].value.a = 0;
			sess->params[i].value.b = 0;
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			sess->params[i].value.a = params[i].value.a;
			sess->params[i].value.b = params[i].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			shm_va = ipc_shm_map(t->proc,
						params[i].memref.buffer,
						params[i].memref.size);
			if (IS_ERR_PTR(shm_va)) {
				ret = PTR_ERR(shm_va);
				goto out;
			}
			sess->params[i].memref.buffer = shm_va;
			sess->params[i].memref.size = params[i].memref.size;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
	}

	sess->cmd = cmd;
	sess->types = params_type;
	sess->cancel_mask = true;
	sess->stat = SESS_PREPARED;
	return 0;

out:
	EMSG("failed %d\n", ret);
	ipc_param_put(params, params_type, t);
	return ret;
}

static int ipc_security_check(const TEE_UUID *uuid)
{
	struct process *proc = current->proc;
	struct process_config *c = process_config_of(uuid);

	if (c == NULL) {
		EMSG("No Such Service\n");
		return -ENOENT;
	}

	/*
	 * check if current TA has permission
	 * to access the target TA
	 */
	if (!strstr_delimiter(proc->c->ipc_acl,
			c->name, ',')) {
		EMSG("TA<->TA IPC permission??\n");
		return -EACCES;
	}

	return 0;
}

static int ipc_audit(struct thread *t)
{
	if (current->proc->id == t->proc->parent_id)
		return 0;

	EMSG("'%s' %d not owner of '%s' %04d|%04d parent=%d\n",
		current->name, current->proc->id, (t)->name,
		(t)->id, (t)->proc->id, (t)->proc->parent_id);

	return -EPERM;
}

static pid_t ipc_session_create(const TEE_UUID *uuid)
{
	pid_t tid = -1;
	struct process *proc = NULL;
	struct process *curr = current->proc;
	struct process_config *c = process_config_of(uuid);
	struct sched_param prio = {.sched_priority
			= PTHREAD_RPC_DEFAULT_PRIORITY};
	DECLARE_DETACHED_PTHREAD_ATTR(attr);

	if (c == NULL) {
		EMSG("No Such Service\n");
		return -ENOENT;
	}

	/*
	 * Privilege TA is only for TEE internal usage
	 */
	if (c->privilege) {
		EMSG("Error target is Privilege TA\n");
		return -EACCES;
	}

	if (!PROCESS_ALIVE(curr)) {
		WMSG("proc is exiting\n");
		return -EINTR;
	}

	if (!c->single_instance) {
		/* use the primary thread */
		tid = process_create(uuid);
		sched_setscheduler(tid, SCHED_OTHER, &prio);
	} else {
		mutex_lock(&c->inst_lock);
		proc = __process_get(c);
		if (proc) {
			if ((c->multi_session == false) ||
				(curr->id != proc->parent_id)) {
				if (c->multi_session == false)
					EMSG("busy! not multi_session\n");
				else
					EMSG("%d not owner of %d parent=%d\n",
						curr->id, proc->id, proc->parent_id);

				__process_put(proc);
				mutex_unlock(&c->inst_lock);
				return -EBUSY;
			}

			attr.stacksize = proc->c->ustack_size;
			attr.schedparam.sched_priority = PTHREAD_RPC_DEFAULT_PRIORITY;
			tid = pthread_kcreate(proc, &attr, NULL, NULL);
			__process_put(proc);
			mutex_unlock(&c->inst_lock);
		} else {
			/* use the primary thread */
			tid = process_create(uuid);
			sched_setscheduler(tid, SCHED_OTHER, &prio);
			mutex_unlock(&c->inst_lock);
		}
	}

	return tid;
}

static struct thread *ipc_session_get(pid_t tid)
{
	int ret = -ESRCH;
	struct thread *t = NULL;
	struct pthread_session *sess = NULL;

	for (;;) {
		t = thread_get(tid);
		if (t == NULL)
			return NULL;

		ret = ipc_audit(t);
		if (ret != 0) {
			thread_put(t);
			return NULL;
		}

		sess = ipc_session(t);

		mutex_lock(&t->mlock);
		if (sess->stat == SESS_DONE)
			break;
		mutex_unlock(&t->mlock);
		thread_put(t);
		usleep(1000);
	}

	return t;
}

static void ipc_session_put(struct thread *t)
{
	mutex_unlock(&t->mlock);
	thread_put(t);
}

static int ipc_session_wait(struct thread *t, uint32_t timeout, bool isopen)
{
	int ret = 0;
	uint64_t remain = 0;
	struct pthread_session *sess = ipc_session(t);

	/*
	 * if timeout == TEE_TIMEOUT_INFINITE, then wait infinitely
	 */
	if (timeout == TEE_TIMEOUT_INFINITE) {
		ret = wait_locked(&t->join_q, &t->mlock);
	} else {
		/* timeout - (microseconds) */
		remain = wait_timeout_locked(&t->join_q, timeout, &t->mlock);
		if (remain == 0) {
			/* according to spec, timeout means cancellation */
			sess->cancel_flag = true;
			if (sess->cancel_mask == false) {
				ret = sigenqueue(t->id, isopen ? SIGKILL : SIGSTOP, SI_QUEUE,
						(union sigval)((void *)TEE_ERROR_CANCEL), true);
				if (ret == 0)
					ret = wait_locked(&t->join_q, &t->mlock);
			} else {
				ret = -ETIMEDOUT;
			}
		} else {
			ret = t->join_q.notification;
		}
	}

	if (ret != 0)
		EMSG("ret=0x%x(%d) sess=%04d timeout=%d\n",
			ret, ret, t->id, (int)timeout);

	return ret;
}

int ipc_session_open(TEE_UUID *uuid,
	uint32_t timeout, uint32_t types, void *param)
{
	int ret = -EINVAL;
	struct thread *t = NULL;

	ret = ipc_security_check(uuid);
	if (ret != 0)
		return ret;

	ret = ipc_session_create(uuid);
	if (ret < 0)
		return ret;

	t = thread_get(ret);
	if (t == NULL)
		return -ESRCH;

	mutex_lock(&t->mlock);

	DMSG("open %d\n", t->id);

	ret = ipc_param_get(param, types, 0, t);
	if (ret != 0) {
		thread_put(t);
		goto out;
	}

	ret = sched_entry_init(t->id,
		t->proc->pself->wrapper.pthread_entry,
		t->proc->pself->wrapper.open, NULL);

	if (ret == 0 && sched_ready(t->id))
		ret = ipc_session_wait(t, timeout, true);

	ipc_param_put(param, types, t);

	if (ret != 0)
		goto out;

	ret = t->id;

out:
	DMSG("open %d ret %d\n", t->id, ret);
	ipc_session_put(t);
	return ret;
}

int ipc_session_invoke(pid_t tid, uint32_t timeout,
	uint32_t cmd, uint32_t types, void *params)
{
	int ret = -EINVAL;
	struct thread *t = NULL;

	t = ipc_session_get(tid);
	if (t == NULL) {
		EMSG("No such session %d\n", tid);
		return -ESRCH;
	}

	DMSG("invoke %d\n", tid);

	ret = ipc_param_get(params, types, cmd, t);
	if (ret != 0)
		goto out;

	ret = sched_entry_init(tid,
		t->proc->pself->wrapper.pthread_entry,
		t->proc->pself->wrapper.invoke, NULL);

	if ((ret == 0) && sched_ready(tid))
		ret = ipc_session_wait(t, timeout, false);

	ipc_param_put(params, types, t);

out:
	DMSG("invoke %d ret %d\n", tid, ret);
	ipc_session_put(t);
	return ret;
}

int ipc_session_close(pid_t tid)
{
	int ret = -ESRCH;
	struct thread *t = NULL;
	struct pthread_session *sess = NULL;

	t = ipc_session_get(tid);
	if (t == NULL) {
		EMSG("No such session %d\n", tid);
		return -ESRCH;
	}

	DMSG("close %d\n", tid);

	sess = ipc_session(t);
	sess->cancel_mask = true;
	sess->stat = SESS_PREPARED;

	ret = sched_entry_init(tid,
		t->proc->pself->wrapper.pthread_entry,
		t->proc->pself->wrapper.close, NULL);

	if (ret == 0 && sched_ready(tid))
		ret = wait_locked(&t->join_q, &t->mlock);

	sess->stat = SESS_DONE;

	DMSG("close %d ret %d\n", tid, ret);
	ipc_session_put(t);
	return ret;
}
