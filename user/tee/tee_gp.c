// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * GP session APIs (GlobalPlatform Style via RPC)
 */

#include <utrace.h>
#include <__process.h>

#include <pthread_session.h>
#include <pthread_mutexdep.h>

extern struct proc_info __proc_info;

static int sess_cnt;

static DECLARE_RECURSIVE_PTHREAD_MUTEX(sess_lock);

static inline void pthread_session_lock(void)
{
	__pthread_mutex_lock(&sess_lock);
}

static inline void pthread_session_unlock(void)
{
	__pthread_mutex_unlock(&sess_lock);
}

static void pthread_sched_suspend(long msg)
{
	syscall1(SYSCALL_SCHED_SUSPEND, msg);

	WMSG("suspend failed ??\n");

	/* normally never run to here */
	pthread_exit((void *)msg);
}

extern void pthread_session_open(void)
{
	long ret = -EACCES;
	struct pthread_session *s = __pthread_sess;
	struct process_gp *gp = &__proc_info.gp;

	pthread_session_lock();

	s->stat = SESS_ENTER_APP;

	if ((sess_cnt == 0) && gp->create) {
		ret = gp->create();
		if (ret != 0)
			goto err;
	}

	ret = gp->open(s->types, s->params,
					&s->session);
	if (ret != 0) {
		if ((sess_cnt == 0) && gp->destroy)
			gp->destroy();
		goto err;
	}

	sess_cnt++;

	s->stat = SESS_LEAVE_APP;

	pthread_session_unlock();

	pthread_sched_suspend(ret);

err:
	pthread_session_unlock();
	s->stat = SESS_LEAVE_APP;
	pthread_exit((void *)ret);
}

extern void pthread_session_invoke(void)
{
	long ret = -EACCES;
	struct pthread_session *s = __pthread_sess;

	s->stat = SESS_ENTER_APP;

	ret = __proc_info.gp.invoke(s->session,
			s->cmd, s->types, s->params);

	s->stat = SESS_LEAVE_APP;

	pthread_sched_suspend(ret);
}

extern void pthread_session_close(void)
{
	struct pthread_session *s = __pthread_sess;
	struct process_gp *gp = &__proc_info.gp;

	pthread_session_lock();

	s->stat = SESS_ENTER_APP;

	sess_cnt--;

	gp->close(s->session);

	if ((sess_cnt == 0) && gp->destroy)
		gp->destroy();

	s->stat = SESS_LEAVE_APP;

	pthread_session_unlock();

	pthread_exit(NULL);
}

bool pthread_session_cancel_flag(void)
{
	struct pthread_session *s = __pthread_sess;
	bool flag = false;

	pthread_session_lock();
	flag = !s->cancel_mask && s->cancel_flag;
	pthread_session_unlock();

	return flag;
}

bool pthread_session_cancel_unmask(void)
{
	bool ret = true;
	struct pthread_session *s = __pthread_sess;

	pthread_session_lock();

	ret = s->cancel_mask;
	s->cancel_mask = false;

	pthread_session_unlock();

	return ret;
}

bool pthread_session_cancel_mask(void)
{
	bool ret = true;
	struct pthread_session *s = __pthread_sess;

	pthread_session_lock();

	ret = s->cancel_mask;
	s->cancel_mask = true;

	pthread_session_unlock();

	return ret;
}
