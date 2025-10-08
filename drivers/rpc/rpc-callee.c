// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RPC Callee (GlobalPlatform Style REE->TA)
 */

#include <init.h>
#include <trace.h>
#include <string.h>
#include <percpu.h>
#include <thread.h>
#include <sched.h>
#include <kthread.h>
#include <tasklet.h>
#include <cpu.h>
#include <timer.h>
#include <kmalloc.h>
#include <delay.h>
#include <kvma.h>
#include <sys/pthread.h>

#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <pthread_session.h>

#include <rpc_callee.h>

struct rpc_work {
	unsigned int fn;
	struct work wk;
	unsigned long remote_phys;
	struct rpc_cmd *remote;
	struct rpc_cmd local;
};

static struct workqueue *rpc_wq;

/*
 * allocate a TEE local rpc work struct and backup
 * the remote params to local, then use this local
 * param to handle RPC to prevent the TOCTOU attack
 *
 * RPC data size shall less then PAGE_SIZE
 */
static struct rpc_work *rpc_work_alloc(unsigned long remote)
{
	int ret = -1;
	struct rpc_cmd *r = NULL;
	struct rpc_work *rpc = NULL;
	size_t payload_size = 0;

	/*
	 * this remote PAGE must within REE memory
	 */
	if (mem_in_secure(remote) || mem_in_secure(remote + PAGE_SIZE)) {
		EMSG("rpc remote error %lx\n", remote);
		return ERR_PTR(-EFAULT);
	}

	r = phys_to_virt(remote);

	if (!access_kern_ok((void *)r, PAGE_SIZE, PG_RW)) {
		EMSG("rpc remote badaddr %lx\n", remote);
		return ERR_PTR(-EFAULT);
	}

	payload_size = r->size;
	if (sizeof(struct rpc_work) + payload_size > PAGE_SIZE) {
		ret = -E2BIG;
		goto out;
	}

	/*
	 * allocate TEE local buff, store params to TEE
	 */
	rpc = kmalloc(sizeof(struct rpc_work) + payload_size);
	if (rpc == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(&rpc->local, r, sizeof(struct rpc_cmd) + payload_size);
	rpc->local.size = payload_size;
	rpc->remote_phys = remote;
	rpc->remote = r;
	ret = 0;

out:
	if (ret != 0)
		return ERR_PTR(ret);
	return rpc;
}

static void rpc_work_free(struct rpc_work *rpc)
{
	struct rpc_cmd *r = rpc->remote;

	r->ret = rpc->local.ret;
	memcpy(r->data, rpc->local.data,
			rpc->local.size);
	kfree(rpc);
}

/*
 * Complete the waiter @ REE client
 */
static void rpc_retclient(struct rpc_work *rpc, int ret)
{
	unsigned long waiter = rpc->remote_phys;

	rpc->local.ret = ret;
	rpc_work_free(rpc);

	rpc_call(RPC_COMPLETE_REE, &waiter, sizeof(waiter));
}

static inline struct pthread_session *rpc_session(
	struct thread *t)
{
	BUILD_ERROR_ON(PTHREAD_SESSION_OFFSET +
		sizeof(struct pthread_session) > PAGE_SIZE);

	return ((struct pthread_session *)((long)(t->tuser)
			+ PTHREAD_SESSION_OFFSET));
}

static inline int rpc_audit(struct thread *t)
{
	/*
	 * REE client is not allowed to invoke the TEE kernel threads,
	 * neither the user threads which are opened by TA, it can
	 * only invoke the threads which are opened by itself
	 */
	if (t->rpc_callee == false) {
		EMSG("Error target is not for REE client\n");
		return -EPERM;
	}

	return 0;
}

static int rpc_param_get(
	struct rpc_work *rpc,
	struct thread *t)
{
	void *shm_buf = NULL;
	int i = 0, type = 0, ret = -1;
	struct rpc_memref *memref = NULL;
	struct pthread_session *sess = rpc_session(t);
	struct rpc_param *rp = (void *)rpc->local.data;

	if (sess->cancel_flag) {
		sess->cancel_flag = false;
		EMSG("cancel_flag set\n");
		return TEE_ERROR_CANCEL;
	}

	for (i = 0; i < 4; i++) {
		type = TEE_PARAM_TYPE_GET(rp->params_type, i);

		switch (type) {
		case TEE_PARAM_TYPE_NONE:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
			memset(&sess->params[i], 0, sizeof(TEE_Param));
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			sess->params[i].value.a = rp->params[i].value.a;
			sess->params[i].value.b = rp->params[i].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			memref = &rp->params[i].memref;
			shm_buf = rpc_gpshm_map(t->proc, memref, PG_RW);
			if (IS_ERR_PTR(shm_buf)) {
				if (memref->size) {
					ret = PTR_ERR(shm_buf);
					goto out;
				}
				shm_buf = NULL;
			}
			sess->params[i].memref.size = memref->size;
			sess->params[i].memref.buffer = shm_buf;
			shm_buf = NULL;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
	}

	sess->cancel_mask = true;
	sess->cmd = rp->cmd_id;
	sess->types = rp->params_type;
	sess->stat = SESS_PREPARED;
	rp->session_id = t->id;
	rp->ret_origin = TEE_ORIGIN_TRUSTED_APP;
	return 0;

out:
	EMSG("failed %d\n", ret);

	while (--i >= 0) {
		type = TEE_PARAM_TYPE_GET(rp->params_type, i);
		if (type == TEE_PARAM_TYPE_MEMREF_INPUT ||
			type == TEE_PARAM_TYPE_MEMREF_INOUT ||
			type == TEE_PARAM_TYPE_MEMREF_OUTPUT)
			rpc_gpshm_unmap(rp->params[i].memref.id);
	}
	return ret;
}

static void rpc_param_put(
	struct rpc_work *rpc,
	struct thread *t)
{
	int i = 0, type = 0;
	struct rpc_param *rp = (void *)rpc->local.data;
	struct pthread_session *sess = rpc_session(t);

	for (i = 0; i < 4; i++) {
		type = TEE_PARAM_TYPE_GET(rp->params_type, i);

		if ((type == TEE_PARAM_TYPE_MEMREF_INOUT) ||
			(type == TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
			rp->params[i].memref.size = sess->params[i].memref.size;
		} else if (
			(type == TEE_PARAM_TYPE_VALUE_OUTPUT) ||
			(type == TEE_PARAM_TYPE_VALUE_INOUT)) {
			rp->params[i].value.a = sess->params[i].value.a;
			rp->params[i].value.b = sess->params[i].value.b;
		}

		if (type == TEE_PARAM_TYPE_MEMREF_INPUT ||
			type == TEE_PARAM_TYPE_MEMREF_INOUT ||
			type == TEE_PARAM_TYPE_MEMREF_OUTPUT)
			rpc_gpshm_unmap(rp->params[i].memref.id);
	}

	sess->cancel_mask = true;
	sess->cancel_flag = false;
	sess->stat = SESS_DONE;
}

static pid_t rpc_session_create(const TEE_UUID *uuid)
{
	pid_t tid = -1;
	struct process *proc = NULL;
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

	if (!c->single_instance) {
		/* use the primary thread */
		tid = process_create(uuid);
		sched_setscheduler(tid, SCHED_OTHER, &prio);
	} else {
		mutex_lock(&c->inst_lock);
		proc = __process_get(c);
		if (proc) {
			if ((c->multi_session == false) ||
				(current->proc->id != proc->parent_id)) {
				if (c->multi_session == false)
					EMSG("busy! not multi_session\n");
				else
					EMSG("%d not owner of %d parent=%d\n",
						current->proc->id, proc->id, proc->parent_id);
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

static struct thread *rpc_session_get(pid_t tid)
{
	int ret = -ESRCH;
	struct thread *t = NULL;
	struct pthread_session *sess = NULL;

	for (;;) {
		t = thread_get(tid);
		if (t == NULL)
			return NULL;

		ret = rpc_audit(t);
		if (ret != 0) {
			thread_put(t);
			return NULL;
		}

		sess = rpc_session(t);

		mutex_lock(&t->mlock);
		if (sess->stat == SESS_DONE)
			break;
		mutex_unlock(&t->mlock);
		thread_put(t);
		usleep(1000);
	}

	return t;
}

static void rpc_session_put(struct thread *t)
{
	mutex_unlock(&t->mlock);
	thread_put(t);
}

static void rpc_octets2uuid(TEE_UUID *dst, unsigned char *src)
{
	memcpy(dst, src, sizeof(TEE_UUID));

	dst->timeLow = bswap32(dst->timeLow);
	dst->timeMid = bswap16(dst->timeMid);
	dst->timeHiAndVersion = bswap16(dst->timeHiAndVersion);
}

static int rpc_session_open(struct rpc_work *rpc)
{
	int ret = -EINVAL, tid = -1;
	struct thread *t = NULL;
	struct rpc_param *rp = (void *)rpc->local.data;
	TEE_UUID uid = {0};

	rp->ret_origin = TEE_ORIGIN_TEE;

	rpc_octets2uuid(&uid, rp->uuid);
	ret = rpc_session_create(&uid);
	if (ret < 0)
		return ret;

	tid = ret;

	t = thread_get(tid);
	if (t == NULL)
		return -ESRCH;

	mutex_lock(&t->mlock);

	DMSG("open %d\n", tid);

	ret = rpc_param_get(rpc, t);
	if (ret != 0) {
		thread_put(t);
		goto out;
	}

	t->rpc_callee = true;

	ret = sched_entry_init(tid,
		t->proc->pself->wrapper.pthread_entry,
		t->proc->pself->wrapper.open, NULL);

	if (ret == 0 && sched_ready(tid))
		ret = wait_locked(&t->join_q, &t->mlock);

	rpc_param_put(rpc, t);

out:
	DMSG("open %d ret %d\n", tid, ret);
	rpc_session_put(t);
	return ret;
}

static int rpc_session_invoke(struct rpc_work *rpc)
{
	int tid = -1;
	int ret = -EINVAL;
	struct thread *t = NULL;
	struct rpc_param *rp = (void *)rpc->local.data;

	tid = rp->session_id;
	rp->ret_origin = TEE_ORIGIN_TEE;

	t = rpc_session_get(tid);
	if (t == NULL) {
		EMSG("No such session %d\n", tid);
		return -ESRCH;
	}

	DMSG("invoke %d\n", tid);
	ret = rpc_param_get(rpc, t);
	if (ret != 0)
		goto out;

	ret = sched_entry_init(tid,
		t->proc->pself->wrapper.pthread_entry,
		t->proc->pself->wrapper.invoke, NULL);

	if (ret == 0 && sched_ready(tid))
		ret = wait_locked(&t->join_q, &t->mlock);

	rpc_param_put(rpc, t);

out:
	DMSG("invoke %d ret %d\n", tid, ret);
	rpc_session_put(t);
	return ret;
}

static int rpc_session_close(struct rpc_work *rpc)
{
	int tid = -1;
	int ret = -EPERM;
	struct thread *t = NULL;
	struct pthread_session *sess = NULL;
	struct rpc_param *rp = (void *)rpc->local.data;

	tid = rp->session_id;
	rp->ret_origin = TEE_ORIGIN_TEE;

	t = rpc_session_get(tid);
	if (t == NULL) {
		EMSG("No such session %d\n", tid);
		return -ESRCH;
	}

	sess = rpc_session(t);

	DMSG("close %d\n", tid);

	t->rpc_callee = false;

	memset(rp, 0, sizeof(struct rpc_param));

	sess->cancel_mask = true;
	sess->stat = SESS_PREPARED;

	ret = sched_entry_init(tid,
		t->proc->pself->wrapper.pthread_entry,
		t->proc->pself->wrapper.close, NULL);

	if (ret == 0 && sched_ready(tid))
		ret = wait_locked(&t->join_q, &t->mlock);

	sess->stat = SESS_DONE;

	DMSG("close %d ret %d\n", tid, ret);
	rpc_session_put(t);
	return ret;
}

/*
 * Cancellation from the REE client
 */
static int rpc_cancel(pid_t tid)
{
	int ret = -1, locked = 0;
	struct thread *t = NULL;
	struct pthread_session *sess = NULL;

	t = thread_get(tid);
	if (t == NULL) {
		EMSG("no such sess=%04d\n", tid);
		return -ESRCH;
	}

	ret = rpc_audit(t);
	if (ret != 0) {
		thread_put(t);
		return ret;
	}

	sess = rpc_session(t);

	locked = mutex_trylock(&t->mlock);
	sess->cancel_flag = true;

	WMSG("sess=%04d cancel_mask=%d\n", tid, sess->cancel_mask);

	if (sess->cancel_mask)
		goto out;

	if (sess->stat == SESS_ENTER_APP) {
		ret = sigenqueue(tid, SIGSTOP, SI_QUEUE,
			(union sigval)((void *)TEE_ERROR_CANCEL), true);
	}

out:
	if (locked)
		mutex_unlock(&t->mlock);
	thread_put(t);
	return ret;
}

static void rpc_yieldcall_handler(struct work *w)
{
	struct rpc_work *rpc = container_of(w, struct rpc_work, wk);
	unsigned int fn = rpc->fn;

	switch (fn) {
	case RPC_OPEN_SESSION:
		rpc_retclient(rpc, rpc_session_open(rpc));
		break;

	case RPC_INVOKE_SESSION:
		rpc_retclient(rpc, rpc_session_invoke(rpc));
		break;

	case RPC_CLOSE_SESSION:
		rpc_retclient(rpc, rpc_session_close(rpc));
		break;

	case RPC_REGISTER_SHM: {
		rpc_retclient(rpc, rpc_gpshm_register((void *)rpc->local.data));
		break;
	}

	case RPC_UNREGISTER_SHM: {
		rpc_retclient(rpc, rpc_gpshm_unregister((void *)rpc->local.data));
		break;
	}

	case RPC_CANCEL: {
		int *tid = (int *)rpc->local.data;

		rpc_retclient(rpc, rpc_cancel(*tid));
		break;
	}

	default:
		EMSG("unknown RPC: 0x%08lx\n", (long)fn);
		rpc_retclient(rpc, -EINVAL);
		break;
	}
}

/* handler for yield calls */
long rpc_yield_handler(unsigned long fn, unsigned long remote)
{
	struct rpc_work *rpc = rpc_work_alloc(remote);

	if (!IS_ERR_PTR(rpc)) {
		/*
		 * Yieldcall handler schedules a work to handle
		 * this remote request, while synchronous handler
		 * handles the request directly in interrupt ctx,
		 * so sleep should be avoid in fastcall handler.
		 */
		rpc->fn = fn;
		INIT_WORK(&rpc->wk, rpc_yieldcall_handler);
		queue_work_on(percpu_id(), rpc_wq, &rpc->wk);
	} else {
		EMSG("rpc_work_alloc failed - %p\n", rpc);
		return PTR_ERR(rpc);
	}

	return 0;
}

static void __init rpc_callee_init(void)
{
	rpc_wq = create_workqueue("rpc");
	assert(rpc_wq);

	workqueue_setscheduler(rpc_wq, SCHED_RR, SCHED_HIGHPRIO_DEFAULT);
}
MODULE_INIT_SYS(rpc_callee_init);
