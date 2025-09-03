// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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
#include <atomic.h>
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

/*
 * REE->TEE yield RPC payloads are protocol-bounded (not arbitrary PAGE_SIZE).
 * Keep the single-pass fixed-size range check, but cap it to the largest
 * defined wire payload so small call buffers aren't rejected by an oversized
 * upfront access check.
 */
#define RPC_MAX_WIRE_PAYLOAD_A \
	((sizeof(struct rpc_param) > sizeof(struct rpc_memref)) ? \
	 sizeof(struct rpc_param) : sizeof(struct rpc_memref))
#define RPC_MAX_PAYLOAD \
	((RPC_MAX_WIRE_PAYLOAD_A > sizeof(struct rpc_cancel_req)) ? \
	 RPC_MAX_WIRE_PAYLOAD_A : sizeof(struct rpc_cancel_req))
#define RPC_CMD_MAX_SIZE (sizeof(struct rpc_cmd) + RPC_MAX_PAYLOAD)

static struct workqueue *rpc_wq;

static struct atomic_num nr_sessions = ATOMIC_INIT(0);

/*
 * Safety-net: if a thread with rpc_callee=true is destroyed
 * without going through rpc_session_close (e.g. TA open fails
 * and the thread exits), decrement the session counter here.
 */
static void rpc_session_cleanup(struct thread *t)
{
	if (t->rpc_callee) {
		t->rpc_callee = false;
		atomic_dec(&nr_sessions);
	}
}
DECLARE_THREAD_CLEANUP(rpc_session_cleanup);

/*
 * Allocate a TEE-local rpc_work struct and copy the remote params to
 * local storage to prevent TOCTOU attacks.
 *
 * Validation is done with a single fixed-size range check
 * (RPC_CMD_MAX_SIZE) so we avoid a two-pass header-then-full-range
 * approach.  The payload size is then verified against RPC_MAX_PAYLOAD
 * before the actual copy.
 *
 * The remote address needs only natural pointer alignment (not page-
 * alignment) and must not reside in TEE secure memory.
 */
static struct rpc_work *rpc_work_alloc(unsigned long remote)
{
	struct rpc_cmd *r = NULL;
	struct rpc_work *rpc = NULL;
	size_t payload_size = 0;
	int ret = -1;

	/*
	 * The remote address must be 4-byte aligned and must not
	 * point into TEE secure memory.
	 */
	if (mem_in_secure(remote) || (remote & 3)) {
		EMSG("rpc remote error %lx\n", remote);
		return ERR_PTR(-EFAULT);
	}

	r = phys_to_virt(remote);

	/* Single-pass: validate the worst-case range once. */
	if (mem_in_secure(remote + RPC_CMD_MAX_SIZE - 1)) {
		EMSG("rpc remote range error %lx\n", remote);
		return ERR_PTR(-EFAULT);
	}

	if (IS_ENABLED(CONFIG_MMU) &&
	    !access_kern_ok((void *)r, RPC_CMD_MAX_SIZE, PG_RW)) {
		EMSG("rpc remote badaddr %lx\n", remote);
		return ERR_PTR(-EFAULT);
	}

	payload_size = r->size;
	if (payload_size > RPC_MAX_PAYLOAD) {
		ret = -E2BIG;
		goto out;
	}

	/*
	 * Allocate TEE local buff, copy params to TEE.
	 */
	rpc = kmalloc(sizeof(struct rpc_work) + payload_size);
	if (!rpc) {
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
 * Session open/invoke publish GP results in rpc_cmd.ret. Convert only local
 * errno-style failures from the callee framework and leave success or already
 * encoded protocol values untouched.
 */
static int rpc_errno_to_gp(struct rpc_work *rpc, int ret)
{
	if (ret >= 0 || ret < -__ELASTERROR)
		return ret;

	switch (ret) {
	case -EPERM:
	case -EACCES:
		return TEE_ERROR_ACCESS_DENIED;
	case -EINTR:
	case -ECANCELED:
		return TEE_ERROR_CANCEL;
	case -E2BIG:
		return TEE_ERROR_EXCESS_DATA;
	case -EINVAL:
	case -EFAULT:
	case -ENOEXEC:
		return TEE_ERROR_BAD_PARAMETERS;
	case -ENOENT:
		return TEE_ERROR_ITEM_NOT_FOUND;
	case -ENOMEM:
		return TEE_ERROR_OUT_OF_MEMORY;
	case -EBUSY:
		return TEE_ERROR_BUSY;
	case -ESRCH: {
		struct rpc_param *rp = NULL;
		rp = (struct rpc_param *)rpc->local.data;
		rp->ret_origin = TEE_ORIGIN_TEE;
		return TEE_ERROR_TARGET_DEAD;
	}
	default:
		return TEE_ERROR_GENERIC;
	}
}

/*
 * Complete the RPC request and notify the waiting REE caller.
 */
static void rpc_retclient(struct rpc_work *rpc, int ret)
{
	/*
	 * Echo the REE-provided sync request ID so REE can resolve the
	 * pending call by waiter_id without relying on rpc_cmd phys reuse.
	 */
	uint64_t wire_waiter_id = rpc->local.waiter_id;

	rpc->local.ret = rpc_errno_to_gp(rpc, ret);

	rpc_work_free(rpc);

	rpc_call(MBEDTEE_RPC_COMPLETE_REE, &wire_waiter_id,
		 sizeof(wire_waiter_id));
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
	 * only invoke the user threads which are opened by itself
	 */
	if (!t->rpc_callee) {
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
	struct process_config *c = process_config_of_uuid(uuid);
	struct sched_param prio = {.sched_priority
			= PTHREAD_RPC_DEFAULT_PRIORITY};
	DECLARE_DETACHED_PTHREAD_ATTR(attr);

	if (!c) {
		EMSG("No Such Service\n");
		return -ENOENT;
	}

	/*
	 * A privileged TA is for TEE internal use only.
	 */
	if (c->privilege) {
		EMSG("Error target is Privilege TA\n");
		return -EACCES;
	}

	if (!c->single_instance) {
		/* use the primary thread */
		tid = __process_create(c, NULL);
		sched_setscheduler(tid, SCHED_OTHER, &prio);
	} else {
		if (mutex_lock_interruptible(&c->inst_lock) != 0)
			return -EINTR;

		proc = __process_get(c);
		if (proc) {
			if (!c->multi_session ||
				(current->proc->id != proc->parent_id)) {
				if (!c->multi_session)
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
			tid = __process_create(c, NULL);
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
		if (!t)
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

static int rpc_session_wait(struct thread *t)
{
	int ret = -1;
	struct pthread_session *sess = rpc_session(t);

	ret = wait_locked_interruptible(&t->join_q, &t->mlock);
	if (ret == -EINTR) {
		sess->cancel_flag = true;
		/*
		 * If cancel_mask is false, the TA is not masking cancellations
		 * (cancellation is enabled), so send the cancel signal to the TA.
		 *
		 * If cancel_mask is true, the TA is masking cancellations,
		 * or it is not running in the TA context (e.g. prepared or done),
		 * so just return the error without signalling.
		 */
		if (!sess->cancel_mask) {
			ret = sigenqueue(t->id, SIGSTOP, SI_QUEUE,
					(union sigval)((void *)TEE_ERROR_CANCEL), true);
			if (ret == 0)
				ret = wait_locked_interruptible(&t->join_q, &t->mlock);
		}
	}

	return ret;
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

	if (atomic_inc_return(&nr_sessions) > CONFIG_RPC_MAX_SESSIONS) {
		EMSG("session limit %d\n", CONFIG_RPC_MAX_SESSIONS);
		ret = -EBUSY;
		goto dec;
	}

	rpc_octets2uuid(&uid, rp->uuid);
	ret = rpc_session_create(&uid);
	if (ret < 0)
		goto dec;

	tid = ret;

	t = thread_get(tid);
	if (!t) {
		ret = -ESRCH;
		goto dec;
	}

	mutex_lock(&t->mlock);

	DMSG("open %d\n", tid);

	ret = rpc_param_get(rpc, t);
	if (ret != 0)
		goto dec;

	t->rpc_callee = true;

	ret = sched_entry_init(tid,
		t->proc->wrapper.pthread_entry,
		t->proc->wrapper.open, NULL);
	if (ret == 0) {
		if (sched_ready(tid))
			ret = rpc_session_wait(t);
		rpc_param_put(rpc, t);
	} else {
		rpc_param_put(rpc, t);
		thread_put(t);
	}

out:
	DMSG("open %d ret %d\n", tid, ret);
	rpc_session_put(t);
	return ret;

dec:
	atomic_dec(&nr_sessions);
	if (t) {
		thread_put(t);
		goto out;
	}
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
	if (!t) {
		EMSG("No such session %d\n", tid);
		return -ESRCH;
	}

	DMSG("invoke %d\n", tid);
	ret = rpc_param_get(rpc, t);
	if (ret != 0)
		goto out;

	ret = sched_entry_init(tid,
		t->proc->wrapper.pthread_entry,
		t->proc->wrapper.invoke, NULL);

	if (ret == 0 && sched_ready(tid))
		ret = rpc_session_wait(t);

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
	if (!t) {
		DMSG("No such session %d\n", tid);
		return -ESRCH;
	}

	sess = rpc_session(t);

	DMSG("close %d\n", tid);

	t->rpc_callee = false;
	atomic_dec(&nr_sessions);

	memset(rp, 0, sizeof(struct rpc_param));

	sess->cancel_mask = true;
	sess->stat = SESS_PREPARED;

	ret = sched_entry_init(tid,
		t->proc->wrapper.pthread_entry,
		t->proc->wrapper.close, NULL);

	if (ret == 0 && sched_ready(tid))
		ret = rpc_session_wait(t);

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
	if (!t) {
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
	case MBEDTEE_RPC_OPEN_SESSION:
		rpc_retclient(rpc, rpc_session_open(rpc));
		break;

	case MBEDTEE_RPC_INVOKE_SESSION:
		rpc_retclient(rpc, rpc_session_invoke(rpc));
		break;

	case MBEDTEE_RPC_CLOSE_SESSION:
		rpc_retclient(rpc, rpc_session_close(rpc));
		break;

	case MBEDTEE_RPC_REGISTER_SHM: {
		rpc_retclient(rpc, rpc_gpshm_register((void *)rpc->local.data));
		break;
	}

	case MBEDTEE_RPC_UNREGISTER_SHM: {
		rpc_retclient(rpc, rpc_gpshm_unregister((void *)rpc->local.data));
		break;
	}

	case MBEDTEE_RPC_CANCEL: {
		struct rpc_cancel_req *cancel =
			(struct rpc_cancel_req *)rpc->local.data;

		rpc_retclient(rpc, rpc_cancel(cancel->session_id));
		break;
	}

	default:
		EMSG("unknown RPC: 0x%08x\n", fn);
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
		 * this remote request, while the fast-call handler
		 * handles the request directly in interrupt context,
		 * so blocking sleep is not allowed in the fast-call handler.
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
