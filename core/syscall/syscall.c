// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * syscall kernel routines
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <trace.h>
#include <device.h>
#include <thread.h>
#include <buddy.h>
#include <sched.h>
#include <mutex.h>
#include <timer.h>
#include <poll.h>
#include <epoll.h>
#include <uaccess.h>
#include <sleep.h>
#include <elf_proc.h>
#include <__pthread.h>
#include <sys/pthread.h>

#include <sbrk.h>
#include <property.h>
#include <syscall.h>

#include <mqueue.h>
#include <kmalloc.h>
#include <ksignal.h>
#include <ktime.h>
#include <sys/time.h>
#include <sys/waitpid.h>

#include <semaphore.h>

#include <sys/eventfd.h>
#include <file.h>
#include <sys/spawn.h>

#include "fops.h"
#include "ulock.h"

typedef long (*syscall_fn)(struct thread_ctx *);

static long __access_deny(pid_t tid)
{
	int ret = -EPERM;
	struct thread *t = NULL;

	if (tid == 0)
		return 0;

	t = thread_get(tid);
	if (!t) {
		DMSG("thread not exist %d\n", tid);
		return -ESRCH;
	}

	/*
	 * only permit intra-process
	 */
	if (current->proc == t->proc)
		ret = 0;
	else
		EMSG("access %04d denied\n", tid);

	thread_put(t);

	return ret;
}

static long syscall_open(struct thread_ctx *regs)
{
	return do_syscall_open((const char *)regs->r[ARG_REG + 1],
		regs->r[ARG_REG + 2], regs->r[ARG_REG + 3]);
}

static long syscall_close(struct thread_ctx *regs)
{
	return do_syscall_close(regs->r[ARG_REG + 1]);
}

static long syscall_write(struct thread_ctx *regs)
{
	return do_syscall_write(regs->r[ARG_REG + 1],
		(const void *)regs->r[ARG_REG + 2],
		regs->r[ARG_REG + 3]);
}

static long syscall_read(struct thread_ctx *regs)
{
	return do_syscall_read(regs->r[ARG_REG + 1],
		(void *)regs->r[ARG_REG + 2],
		regs->r[ARG_REG + 3]);
}

static long syscall_ioctl(struct thread_ctx *regs)
{
	return do_syscall_ioctl(regs->r[ARG_REG + 1],
		regs->r[ARG_REG + 2], regs->r[ARG_REG + 3]);
}

static long syscall_lseek(struct thread_ctx *regs)
{
	return do_syscall_lseek(regs->r[ARG_REG + 1],
		regs->r[ARG_REG + 2], regs->r[ARG_REG + 3]);
}

static long syscall_remove(struct thread_ctx *regs)
{
	return do_syscall_unlink((const char *)regs->r[ARG_REG + 1]);
}

static long syscall_fstat(struct thread_ctx *regs)
{
	return do_syscall_fstat(regs->r[ARG_REG + 1],
		(struct stat *)regs->r[ARG_REG + 2]);
}

static long syscall_rename(struct thread_ctx *regs)
{
	return do_syscall_rename(
		(const char *)regs->r[ARG_REG + 1],
		(const char *)regs->r[ARG_REG + 2]
	);
}

static long syscall_ftruncate(struct thread_ctx *regs)
{
	return do_syscall_ftruncate(
		regs->r[ARG_REG + 1],
		regs->r[ARG_REG + 2]);
}

static long syscall_usleep(struct thread_ctx *regs)
{
	return usleep(regs->r[ARG_REG + 1]);
}

static long syscall_msleep(struct thread_ctx *regs)
{
	return msleep(regs->r[ARG_REG + 1]);
}

static long syscall_sched_setscheduler(struct thread_ctx *regs)
{
	long ret = -1;
	pid_t tid = regs->r[ARG_REG + 1];
	int policy = regs->r[ARG_REG + 2];
	void *param = (void *)regs->r[ARG_REG + 3];
	struct sched_param p;

	if (!param)
		return -EINVAL;

	ret = __access_deny(tid);
	if (ret != 0)
		return ret;

	ret = copy_from_user(&p, param, sizeof(p));
	if (ret != 0)
		return -EFAULT;

	if (!SCHED_VALID_USER_POLICY(policy))
		return -EINVAL;

	if (!SCHED_VALID_USER_PARAM(p) &&
		!current->proc->c->privilege)
		return -EINVAL;

	return sched_setscheduler(tid, policy, &p);
}

static long syscall_sched_getscheduler(struct thread_ctx *regs)
{
	long ret = -1;
	pid_t tid = regs->r[ARG_REG + 1];

	ret = __access_deny(tid);
	if (ret != 0)
		return ret;

	return sched_getscheduler(tid);
}

static long syscall_sched_setparam(struct thread_ctx *regs)
{
	long ret = -1;
	pid_t tid = regs->r[ARG_REG + 1];
	void *param = (void *)regs->r[ARG_REG + 2];
	struct sched_param p;

	if (!param)
		return -EINVAL;

	ret = __access_deny(tid);
	if (ret != 0)
		return ret;

	ret = copy_from_user(&p, param, sizeof(p));
	if (ret != 0)
		return -EFAULT;

	if (!SCHED_VALID_USER_PARAM(p) &&
		!current->proc->c->privilege)
		return -EINVAL;

	return sched_setparam(tid, &p);
}

static long syscall_sched_getparam(struct thread_ctx *regs)
{
	long ret = -1;
	pid_t tid = regs->r[ARG_REG + 1];
	void *param = (void *)regs->r[ARG_REG + 2];
	struct sched_param p;

	if (!param)
		return -EINVAL;

	ret = __access_deny(tid);
	if (ret != 0)
		return ret;

	memset(&p, 0, sizeof(p));
	ret = sched_getparam(tid, &p);
	if (ret == 0)
		ret = copy_to_user(param, &p, sizeof(p));
	return ret;
}

static long syscall_sched_setaffinity(struct thread_ctx *regs)
{
	long ret = -1;
	pid_t tid = regs->r[ARG_REG + 1];
	size_t cpusetsz = regs->r[ARG_REG + 2];
	void *param = (void *)regs->r[ARG_REG + 3];
	cpu_set_t p[CPUSET_MAX_CPUS/CPUSET_DEFAULT_CPUS];

	if (!param)
		return -EFAULT;

	if (cpusetsz > CPUSET_MAX_CPUS / 8)
		return -EINVAL;

	ret = __access_deny(tid);
	if (ret != 0)
		return ret;

	ret = copy_from_user(p, param, cpusetsz);
	if (ret != 0)
		return -EFAULT;

	return sched_setaffinity(tid, cpusetsz, p);
}

static long syscall_sched_getaffinity(struct thread_ctx *regs)
{
	long ret = -1;
	pid_t tid = regs->r[ARG_REG + 1];
	size_t cpusetsz = regs->r[ARG_REG + 2];
	void *param = (void *)regs->r[ARG_REG + 3];
	cpu_set_t p[CPUSET_MAX_CPUS/CPUSET_DEFAULT_CPUS];

	if (!param)
		return -EFAULT;

	if (cpusetsz > CPUSET_MAX_CPUS / 8)
		return -EINVAL;

	ret = __access_deny(tid);
	if (ret != 0)
		return ret;

	memset(p, 0, sizeof(p));
	ret = sched_getaffinity(tid, cpusetsz, p);
	if (ret == 0)
		ret = copy_to_user(param, &p, cpusetsz);

	return ret;
}

static long syscall_sched_get_priority_max(struct thread_ctx *regs)
{
	return SCHED_PRIO_USER_MAX;
}

static long syscall_sched_get_priority_min(struct thread_ctx *regs)
{
	return SCHED_PRIO_USER_MIN;
}

static long syscall_sched_yield(struct thread_ctx *regs)
{
	schedule();
	return (long)regs;
}

static long syscall_sched_suspend(struct thread_ctx *regs)
{
	sched_suspend(regs);
	return (long)regs;
}

static long syscall_clockgettime(struct thread_ctx *regs)
{
	long ret = -1;
	struct timespec ts;
	clockid_t clockid = regs->r[ARG_REG + 1];
	struct timespec *uts = (void *)regs->r[ARG_REG + 2];
	struct timezone *utz = (void *)regs->r[ARG_REG + 3];

	if (!uts)
		return -EINVAL;

	ret = clock_gettime(clockid, &ts);
	if (ret != 0)
		return ret;

	ret = copy_to_user(uts, &ts, sizeof(ts));
	if (ret != 0)
		return ret;

	if (utz) {
		struct timezone ktz;

		get_systz(&ktz.tz_minuteswest, &ktz.tz_dsttime);
		ret = copy_to_user(utz, &ktz, sizeof(ktz));
	}

	return ret;
}

static long syscall_clockgetres(struct thread_ctx *regs)
{
	long ret = -1;
	struct timespec ts;
	clockid_t clockid = regs->r[ARG_REG + 1];
	struct timespec *uts = (void *)regs->r[ARG_REG + 2];

	if (!uts)
		return -EINVAL;

	ret = clock_getres(clockid, &ts);
	if (ret != 0)
		return ret;

	return copy_to_user(uts, &ts, sizeof(ts));
}

static long syscall_timer_create(struct thread_ctx *regs)
{
	int ret = -1;
	clockid_t clockid = regs->r[ARG_REG + 1];
	struct sigevent *uevp = (void *)regs->r[ARG_REG + 2];
	timer_t *utimerid = (void *)regs->r[ARG_REG + 3];
	timer_t timerid = -1;
	pthread_attr_t attr;
	struct sigevent evp;

	if (uevp) {
		ret = copy_from_user(&evp, uevp, sizeof(evp));
		if (ret != 0)
			return -EFAULT;

		if ((evp.sigev_notify == SIGEV_THREAD) &&
				evp.sigev_notify_attributes) {
			ret = copy_from_user(&attr, evp.sigev_notify_attributes, sizeof(attr));
			if (ret != 0)
				return -EFAULT;
			evp.sigev_notify_attributes = &attr;
		}
	}

	ret = timer_create(clockid, uevp ? &evp : NULL, &timerid);
	if (ret != 0)
		return ret;

	ret = copy_to_user(utimerid, &timerid, sizeof(timerid));
	if (ret != 0) {
		timer_delete(timerid);
		return -EFAULT;
	}

	return 0;
}

static long syscall_timer_delete(struct thread_ctx *regs)
{
	timer_t id = (timer_t)regs->r[ARG_REG + 1];

	return timer_delete(id);
}

static long syscall_timer_settime(struct thread_ctx *regs)
{
	int ret = -1;
	long args[4] = {0};
	struct itimerspec v;
	struct itimerspec ov;

	if (copy_from_user(args, (void *)regs->r[ARG_REG + 1], sizeof(args)))
		return -EFAULT;

	if (copy_from_user(&v, (void *)args[2], sizeof(v)))
		return -EFAULT;

	if (args[3] && !access_ok(args[3], sizeof(ov)))
		return -EFAULT;

	ret = timer_settime(args[0], args[1], &v, args[3] ? &ov : NULL);
	if (ret != 0)
		return ret;

	if (args[3] && (copy_to_user((void *)args[3], &ov, sizeof(ov))))
		return -EFAULT;

	return 0;
}

static long syscall_timer_gettime(struct thread_ctx *regs)
{
	int ret = -EINVAL;
	struct itimerspec ov;

	ret = timer_gettime(regs->r[ARG_REG + 1], &ov);
	if (ret != 0)
		return ret;

	if (copy_to_user((void *)regs->r[ARG_REG + 2], &ov, sizeof(ov)))
		return -EFAULT;

	return 0;
}

static long syscall_timer_getoverrun(struct thread_ctx *regs)
{
	return timer_getoverrun(regs->r[ARG_REG + 1]);
}

static long syscall_mkdir(struct thread_ctx *regs)
{
	return do_syscall_mkdir((const char *)regs->r[ARG_REG + 1],
			regs->r[ARG_REG + 2]);
}

static long syscall_rmdir(struct thread_ctx *regs)
{
	return do_syscall_rmdir((const char *)regs->r[ARG_REG + 1]);
}

static long syscall_readdir(struct thread_ctx *regs)
{
	return do_syscall_readdir(regs->r[ARG_REG + 1],
			(void *)regs->r[ARG_REG + 2],
			regs->r[ARG_REG + 3]);
}

static long syscall_sbrk(struct thread_ctx *regs)
{
	return sbrk_incr(regs->r[ARG_REG + 1]);
}

static long syscall_mmap(struct thread_ctx *regs)
{
	long args[6] = {0};

	if (copy_from_user(args, (void *)regs->r[ARG_REG + 1], sizeof(args)))
		return -EFAULT;

	return do_syscall_mmap((void *)args[0], args[1],
				args[2], args[3],
				args[4], args[5]);
}

static long syscall_munmap(struct thread_ctx *regs)
{
	return do_syscall_munmap((void *)regs->r[ARG_REG + 1],
		regs->r[ARG_REG + 2]);
}

static long syscall_poll(struct thread_ctx *regs)
{
	return IS_ENABLED(CONFIG_POLL) ?
		do_syscall_poll((void *)regs->r[ARG_REG + 1],
			regs->r[ARG_REG + 2], regs->r[ARG_REG + 3]) :
			-ENOSYS;
}

static long syscall_select(struct thread_ctx *regs)
{
	long args[5] = {0};
	struct timeval *utv = NULL;
	struct timespec ts, *tsp = NULL;

	if (copy_from_user(&args,
		(void *)regs->r[ARG_REG + 1],
		sizeof(args)))
		return -EFAULT;

	utv = (struct timeval *)args[4];
	if (utv) {
		struct timeval tv;

		if (copy_from_user(&tv, utv, sizeof(tv)))
			return -EFAULT;
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec * 1000L;
		tsp = &ts;
	}

	return do_syscall_select(args[0], (void *)args[1],
		(void *)args[2], (void *)args[3], tsp, NULL);
}

static long syscall_pselect(struct thread_ctx *regs)
{
	long args[6] = {0};
	struct timespec *uts = NULL;
	struct timespec ts, *tsp = NULL;

	if (copy_from_user(&args,
		(void *)regs->r[ARG_REG + 1],
		sizeof(args)))
		return -EFAULT;

	uts = (struct timespec *)args[4];
	if (uts) {
		if (copy_from_user(&ts, uts, sizeof(ts)))
			return -EFAULT;
		tsp = &ts;
	}

	return do_syscall_select(args[0], (void *)args[1],
		(void *)args[2], (void *)args[3],
		tsp, (void *)args[5]);
}

static long syscall_pthread_create(struct thread_ctx *regs)
{
	long ret = 0;
	pthread_attr_t attr;
	struct thread *t = NULL;
	struct process *proc = current->proc;
	void *uattr = (void *)regs->r[ARG_REG + 1];
	int id = -1;

	if (uattr && copy_from_user(&attr, uattr, sizeof(attr)))
		return -EFAULT;

	id = pthread_kcreate(proc, uattr ? &attr : NULL,
				(void *)regs->r[ARG_REG + 2],
				(void *)regs->r[ARG_REG + 3]);
	if (id < 0)
		return id;

	t = thread_get(id);
	ret = t ? (long)t->tuser_uva : -ESRCH;
	thread_put(t);

	sched_ready(id);

	return ret;
}

static long syscall_pthread_exit(struct thread_ctx *regs)
{
	sched_exit(regs);
	return (long)regs;
}

static long syscall_exit(struct thread_ctx *regs)
{
	long lastwords = regs->r[ARG_REG + 1];
	struct process *p = current->proc;

	local_irq_disable();

	/* Save raw exit code for waitpid() */
	p->exit_code = lastwords;

	/* set alive to negative */
	atomic_set(&p->alive, -(INT_MAX >> 1));

	/* send SIGKILL to all the threads @ process */
	sigenqueue(p->id, SIGKILL, SI_QUEUE,
			(union sigval)((void *)lastwords), false);

	/* exit current thread */
	sched_exit(regs);

	/* never runs to here */
	return 0;
}

static long syscall_execve(struct thread_ctx *regs)
{
	int ret = -1;
	char name[PROCESS_NAME_LEN];
	const char *uname = (void *)regs->r[ARG_REG + 1];
	char * const *uargv = (void *)regs->r[ARG_REG + 2];
	pid_t pid = 0;

	ret = strncpy_from_user(name, uname, sizeof(name));
	if (ret < 0)
		return ret;

	if (uargv && !access_ok(uargv, MAX_ARGV_NUM * sizeof(char *)))
		return -EFAULT;

	/*
	 * Legacy/non-POSIX execve behavior: spawn a new process and terminate
	 * the current one. This keeps the API available without requiring
	 * in-place address-space replacement.
	 */
	/* Close CLOEXEC fds in the current process to emulate execve semantics. */
	fdesc_close_cloexec(current->proc);
	pid = process_run(name, uargv);
	if (pid < 0)
		return pid;

	/*
	 * send SIGKILL to all the threads @ process
	 * SIGKILL terminates the current process
	 */
	sigenqueue(current_id, SIGKILL, SI_QUEUE,
			(union sigval)(NULL), false);

	return 0;
}

static long syscall_dup(struct thread_ctx *regs)
{
	return sys_dup(regs->r[ARG_REG + 1]);
}

static long syscall_dup2(struct thread_ctx *regs)
{
	return sys_dup2(regs->r[ARG_REG + 1], regs->r[ARG_REG + 2]);
}

static long syscall_fcntl(struct thread_ctx *regs)
{
	return sys_fcntl(regs->r[ARG_REG + 1], regs->r[ARG_REG + 2],
		regs->r[ARG_REG + 3]);
}

static long syscall_pipe(struct thread_ctx *regs)
{
	long ret = -1;
	int kfds[2] = {-1, -1};
	int *ufds = (void *)regs->r[ARG_REG + 1];
	int flags = regs->r[ARG_REG + 2];

	if (!ufds)
		return -EFAULT;

	if (!access_ok(ufds, sizeof(kfds)))
		return -EFAULT;

	ret = IS_ENABLED(CONFIG_IPC_PIPE) ? sys_pipe2(kfds, flags) : -ENOSYS;
	if (ret != 0)
		return ret;

	if (copy_to_user(ufds, kfds, sizeof(kfds))) {
		/* best effort cleanup */
		sys_close(kfds[0]);
		sys_close(kfds[1]);
		return -EFAULT;
	}

	return 0;
}

static long syscall_eventfd2(struct thread_ctx *regs)
{
	unsigned int initval = regs->r[ARG_REG + 1];
	int flags = regs->r[ARG_REG + 2];

	return IS_ENABLED(CONFIG_IPC_EVENTFD) ? sys_eventfd2(initval, flags) : -ENOSYS;
}

static long syscall_sem_init(struct thread_ctx *regs)
{
	long ret = -1;
	sem_t ksem = {0};
	sem_t *usem = (void *)regs->r[ARG_REG + 1];
	int pshared = regs->r[ARG_REG + 2];
	unsigned int value = regs->r[ARG_REG + 3];

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;
	if (!usem)
		return -EFAULT;
	if (!access_ok(usem, sizeof(ksem)))
		return -EFAULT;
	if (copy_from_user(&ksem, usem, sizeof(ksem)))
		return -EFAULT;

	ret = sem_init(&ksem, pshared, value);
	if (ret != 0)
		return ret;

	if (copy_to_user(usem, &ksem, sizeof(ksem))) {
		/* best effort rollback */
		sem_destroy(&ksem);
		return -EFAULT;
	}

	return 0;
}

static long syscall_sem_destroy(struct thread_ctx *regs)
{
	long ret = -1;
	sem_t ksem = {0};
	sem_t *usem = (void *)regs->r[ARG_REG + 1];

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;
	if (!usem)
		return -EFAULT;
	if (!access_ok(usem, sizeof(ksem)))
		return -EFAULT;
	if (copy_from_user(&ksem, usem, sizeof(ksem)))
		return -EFAULT;

	ret = sem_destroy(&ksem);
	if (ret != 0)
		return ret;

	if (copy_to_user(usem, &ksem, sizeof(ksem)))
		return -EFAULT;

	return 0;
}

static long syscall_sem_post(struct thread_ctx *regs)
{
	sem_t ksem = {0};
	sem_t *usem = (void *)regs->r[ARG_REG + 1];

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;
	if (!usem)
		return -EFAULT;
	if (!access_ok(usem, sizeof(ksem)))
		return -EFAULT;
	if (copy_from_user(&ksem, usem, sizeof(ksem)))
		return -EFAULT;

	return sem_post(&ksem);
}

static long syscall_sem_wait(struct thread_ctx *regs)
{
	sem_t ksem = {0};
	sem_t *usem = (void *)regs->r[ARG_REG + 1];

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;
	if (!usem)
		return -EFAULT;
	if (!access_ok(usem, sizeof(ksem)))
		return -EFAULT;
	if (copy_from_user(&ksem, usem, sizeof(ksem)))
		return -EFAULT;

	return sem_wait(&ksem);
}

static long syscall_sem_trywait(struct thread_ctx *regs)
{
	sem_t ksem = {0};
	sem_t *usem = (void *)regs->r[ARG_REG + 1];

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;
	if (!usem)
		return -EFAULT;
	if (!access_ok(usem, sizeof(ksem)))
		return -EFAULT;
	if (copy_from_user(&ksem, usem, sizeof(ksem)))
		return -EFAULT;

	return sem_trywait(&ksem);
}

static long syscall_sem_timedwait(struct thread_ctx *regs)
{
	sem_t ksem = {0};
	struct timespec ts = {0};
	sem_t *usem = (void *)regs->r[ARG_REG + 1];
	const struct timespec *uts = (void *)regs->r[ARG_REG + 2];

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;
	if (!usem || !uts)
		return -EFAULT;
	if (!access_ok(usem, sizeof(ksem)))
		return -EFAULT;
	if (copy_from_user(&ksem, usem, sizeof(ksem)))
		return -EFAULT;
	if (!access_ok(uts, sizeof(ts)))
		return -EFAULT;
	if (copy_from_user(&ts, uts, sizeof(ts)))
		return -EFAULT;

	return sem_timedwait(&ksem, &ts);
}

static long syscall_sem_getvalue(struct thread_ctx *regs)
{
	long ret = -1;
	sem_t ksem = {0};
	int v = 0;
	sem_t *usem = (void *)regs->r[ARG_REG + 1];
	int *usval = (void *)regs->r[ARG_REG + 2];

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;
	if (!usem || !usval)
		return -EFAULT;
	if (!access_ok(usem, sizeof(ksem)))
		return -EFAULT;
	if (!access_ok(usval, sizeof(int)))
		return -EFAULT;
	if (copy_from_user(&ksem, usem, sizeof(ksem)))
		return -EFAULT;

	ret = sem_getvalue(&ksem, &v);
	if (ret != 0)
		return ret;
	if (copy_to_user(usval, &v, sizeof(v)))
		return -EFAULT;
	return 0;
}

static long syscall_sem_open(struct thread_ctx *regs)
{
	long args[5] = {0};
	char name[SEM_NAME_MAX + 2] = {0};
	long n = 0;
	sem_t ksem = {0};
	sem_t *usem_out = NULL;

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;

	if (copy_from_user(args, (void *)regs->r[ARG_REG + 1], sizeof(args)))
		return -EFAULT;

	usem_out = (sem_t *)args[4];
	if (!usem_out)
		return -EFAULT;
	if (!access_ok(usem_out, sizeof(ksem)))
		return -EFAULT;

	n = strncpy_from_user(name, (const char *)args[0], SEM_NAME_MAX + 1);
	if (n < 0)
		return n;
	if (n == 0)
		return -EINVAL;
	name[SEM_NAME_MAX + 1] = 0;

	{
		sem_t *ksemp = sem_open(name, args[1], args[2], args[3]);
		if (IS_ERR_PTR(ksemp))
			return PTR_ERR(ksemp);

		ksem = *ksemp;
		kfree(ksemp);
	}

	if (copy_to_user(usem_out, &ksem, sizeof(ksem))) {
		/* best effort rollback */
		sem_close(&ksem);
		return -EFAULT;
	}

	return 0;
}

static long syscall_sem_close(struct thread_ctx *regs)
{
	long ret = -1;
	sem_t ksem = {0};
	sem_t *usem = (void *)regs->r[ARG_REG + 1];

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;
	if (!usem)
		return -EFAULT;
	if (!access_ok(usem, sizeof(ksem)))
		return -EFAULT;
	if (copy_from_user(&ksem, usem, sizeof(ksem)))
		return -EFAULT;

	ret = sem_close(&ksem);
	if (ret != 0)
		return ret;

	if (copy_to_user(usem, &ksem, sizeof(ksem)))
		return -EFAULT;

	return 0;
}

static long syscall_wait_rdlock(struct thread_ctx *regs)
{
	return do_syscall_wait_rdlock(regs);
}

static long syscall_wait_wrlock(struct thread_ctx *regs)
{
	return do_syscall_wait_wrlock(regs);
}

static long syscall_wake_lock(struct thread_ctx *regs)
{
	return do_syscall_wake_lock(regs);
}

static long syscall_wait(struct thread_ctx *regs)
{
	long ret = -1, timeout = regs->r[ARG_REG + 1];
	struct thread *t = current;

	/*
	 * if timeout == 0, then wait infinitely
	 */
	if (timeout != 0)
		ret = wait_timeout_interruptible(&t->wait_q, timeout);
	else
		ret = wait_interruptible(&t->wait_q);

	return ret;
}

static long syscall_wake(struct thread_ctx *regs)
{
	long ret = -1;
	int tid = regs->r[ARG_REG + 1];
	struct thread *t = NULL;

	ret = __access_deny(tid);
	if (ret != 0)
		return ret;

	/* wakeup the waiters */
	t = thread_get(tid);
	if (t) {
		wakeup(&t->wait_q);
		thread_put(t);
	}

	return 0;
}

static long syscall_mq_open(struct thread_ctx *regs)
{
	long args[4] = {0}, ret = -1;
	struct mq_attr *uattr = NULL, attr;
	char name[FS_PATH_MAX + 1] = {0};
	long n = 0;

	if (copy_from_user(&args,
		(void *)regs->r[ARG_REG + 1],
		sizeof(args)))
		return -EFAULT;

	uattr = (struct mq_attr *)args[3];

	if (uattr && copy_from_user(&attr,
		uattr, sizeof(attr)))
		return -EFAULT;

	n = strncpy_from_user(name, (const char *)args[0], FS_PATH_MAX);
	if (n < 0)
		return n;
	if (n == 0)
		return -EINVAL;
	if (n >= FS_PATH_MAX)
		return -ENAMETOOLONG;
	name[FS_PATH_MAX] = 0;

	ret = mq_open(name, args[1], (mode_t)args[2], uattr ? &attr : NULL);
	return ret;
}

static long syscall_mq_unlink(struct thread_ctx *regs)
{
	long n = 0;
	const char *uname = (const char *)regs->r[ARG_REG + 1];
	char name[FS_PATH_MAX + 1] = {0};

	if (!uname)
		return -EFAULT;

	n = strncpy_from_user(name, uname, FS_PATH_MAX);
	if (n < 0)
		return n;
	if (n == 0)
		return -EINVAL;
	if (n >= FS_PATH_MAX)
		return -ENAMETOOLONG;
	name[FS_PATH_MAX] = 0;

	return mq_unlink(name);
}

static long syscall_mq_timedsend(struct thread_ctx *regs)
{
	long args[5] = {0}, ret = -1;

	if (copy_from_user(&args,
		(void *)regs->r[ARG_REG + 1],
		sizeof(args)))
		return -EFAULT;

	if (!access_ok((void *)args[1], args[2]))
		return -EFAULT;

	ret = mq_timedsend(args[0], (void *)args[1], args[2],
				args[3], (void *)args[4]);

	return ret;
}

static long syscall_mq_timedreceive(struct thread_ctx *regs)
{
	long args[5] = {0}, ret = -1;

	if (copy_from_user(&args,
		(void *)regs->r[ARG_REG + 1],
		sizeof(args)))
		return -EFAULT;

	if (!access_ok((void *)args[1], args[2]))
		return -EFAULT;

	ret = mq_timedreceive(args[0], (void *)args[1], args[2],
				(void *)args[3], (void *)args[4]);

	return ret;
}

static long syscall_mq_sendfd(struct thread_ctx *regs)
{
	return mq_send_fd(regs->r[ARG_REG + 1], regs->r[ARG_REG + 2]);
}

static long syscall_mq_receivefd(struct thread_ctx *regs)
{
	int fd = -1, ret = -1;

	ret = mq_receive_fd(regs->r[ARG_REG + 1], &fd);
	if (ret != 0)
		return ret;

	if (copy_to_user((void *)regs->r[ARG_REG + 2],
			&fd, sizeof(fd)))
		return -EFAULT;

	return 0;
}

static long syscall_mq_notify(struct thread_ctx *regs)
{
	long ret = -1;
	mqd_t mqdes = (mqd_t)regs->r[ARG_REG + 1];
	struct sigevent *uevp = (void *)regs->r[ARG_REG + 2];
	struct sigevent evp;
	pthread_attr_t attr;

	if (uevp) {
		ret = copy_from_user(&evp, uevp, sizeof(evp));
		if (ret != 0)
			return -EFAULT;

		if ((evp.sigev_notify == SIGEV_THREAD) &&
				evp.sigev_notify_attributes) {
			ret = copy_from_user(&attr, evp.sigev_notify_attributes, sizeof(attr));
			if (ret != 0)
				return -EFAULT;
			evp.sigev_notify_attributes = &attr;
		}
	}

	return mq_notify(mqdes, uevp ? &evp : NULL);
}

static long syscall_mq_getsetattr(struct thread_ctx *regs)
{
	long ret = -1;
	mqd_t mqdes = (mqd_t)regs->r[ARG_REG + 1];
	struct mq_attr *mqstat = (void *)regs->r[ARG_REG + 2];
	struct mq_attr *omqstat = (void *)regs->r[ARG_REG + 3];
	struct mq_attr nstat, ostat = {0};

	if (mqstat && copy_from_user(&nstat, mqstat, sizeof(nstat)))
		return -EFAULT;

	ret = mq_setattr(mqdes, mqstat ? &nstat : NULL,
			omqstat ? &ostat : NULL);
	if (ret != 0)
		return ret;

	if (omqstat && copy_to_user(omqstat, &ostat, sizeof(ostat)))
		return -EFAULT;

	return 0;
}

static long syscall_pause(struct thread_ctx *regs)
{
	return pause();
}

static long syscall_sem_unlink(struct thread_ctx *regs)
{
	long n = 0;
	const char *uname = (const char *)regs->r[ARG_REG + 1];
	char name[SEM_NAME_MAX + 1] = {0};

	if (!IS_ENABLED(CONFIG_IPC_SEM))
		return -ENOSYS;
	if (!uname)
		return -EFAULT;

	n = strncpy_from_user(name, uname, SEM_NAME_MAX);
	if (n < 0)
		return n;
	if (n == 0)
		return -EINVAL;
	if (n >= SEM_NAME_MAX)
		return -ENAMETOOLONG;
	name[SEM_NAME_MAX] = 0;

	return sem_unlink(name);
}

static long syscall_sigaction(struct thread_ctx *regs)
{
	long ret = -1;
	struct sigaction *act_u = (void *)regs->r[ARG_REG + 2];
	struct sigaction *oact_u = (void *)regs->r[ARG_REG + 3];
	struct sigaction act, oact = {0};

	if (act_u && copy_from_user(&act, act_u, sizeof(act)))
		return -EFAULT;

	ret = sigaction(regs->r[ARG_REG + 1],
			act_u ? &act : NULL,
			oact_u ? &oact : NULL);
	if (ret != 0)
		return ret;

	if (oact_u && copy_to_user(oact_u, &oact, sizeof(oact)))
		return -EFAULT;

	return 0;
}

static long syscall_sigprocmask(struct thread_ctx *regs)
{
	long ret = -1;
	sigset_t *set_u = (void *)regs->r[ARG_REG + 2];
	sigset_t *oset_u = (void *)regs->r[ARG_REG + 3];
	sigset_t set, oset = 0;

	if (set_u && copy_from_user(&set, set_u, sizeof(set)))
		return -EFAULT;

	ret = sigprocmask(regs->r[ARG_REG + 1],
					set_u ? &set : NULL,
					oset_u ? &oset : NULL);
	if (ret != 0)
		return ret;

	if (oset_u && copy_to_user(oset_u, &oset, sizeof(oset)))
		return -EFAULT;

	return 0;
}

static long syscall_sigqueue(struct thread_ctx *regs)
{
	long args[5] = {0};
	union sigval v;

	if (copy_from_user(&args, (void *)regs->r[ARG_REG + 1], sizeof(args)))
		return -EFAULT;

	/* Only SI_USER and SI_QUEUE are permitted from user-space */
	if (args[2] != SI_USER && args[2] != SI_QUEUE)
		return -EINVAL;

	v.sival_ptr = (void *)args[3];
	return sigenqueue(args[0], args[1], args[2], v, args[4]);
}

static long syscall_sigreturn(struct thread_ctx *regs)
{
	return (long)sched_sigreturn(regs);
}

static long syscall_sigpending(struct thread_ctx *regs)
{
	long ret = -1;
	sigset_t *argu = (void *)regs->r[ARG_REG + 1];
	sigset_t pending = 0;

	if (!argu || copy_from_user(&pending, argu, sizeof(pending)))
		return -EFAULT;

	ret = sigpending(&pending);
	if (ret != 0)
		return ret;

	if (copy_to_user(argu, &pending, sizeof(pending)))
		return -EFAULT;

	return 0;
}

static long syscall_sigtimedwait(struct thread_ctx *regs)
{
	long ret = -1;
	sigset_t *set_u = (void *)regs->r[ARG_REG + 1], set;
	siginfo_t *info_u = (void *)regs->r[ARG_REG + 2], info;
	struct timespec *ts_u = (void *)regs->r[ARG_REG + 3], ts;

	if (!set_u || copy_from_user(&set, set_u, sizeof(set)))
		return -EFAULT;

	if (ts_u && copy_from_user(&ts, ts_u, sizeof(ts)))
		return -EFAULT;

	memset(&info, 0, sizeof(info));
	ret = sigtimedwait(&set, &info,
					ts_u ? &ts : NULL);
	if (ret <= 0)
		return ret;

	if (info_u && copy_to_user(info_u, &info, sizeof(info)))
		return -EFAULT;

	return ret;
}

static long syscall_sigsuspend(struct thread_ctx *regs)
{
	sigset_t *set_u = (void *)regs->r[ARG_REG + 1], set;

	if (!set_u || copy_from_user(&set, set_u, sizeof(set)))
		return -EFAULT;

	return sigsuspend(&set);
}

static long syscall_sigaltstack(struct thread_ctx *regs)
{
	stack_t *ss_u = (void *)regs->r[ARG_REG + 1];
	stack_t *old_ss_u = (void *)regs->r[ARG_REG + 2];
	stack_t ss, old_ss;
	int ret = 0;

	if (ss_u && copy_from_user(&ss, ss_u, sizeof(ss)))
		return -EFAULT;

	ret = sigaltstack(ss_u ? &ss : NULL, &old_ss);

	/*
	 * POSIX: old_ss must be populated even on failure
	 * (e.g. ENOMEM from MINSIGSTKSZ check).
	 */
	if (old_ss_u && copy_to_user(old_ss_u, &old_ss, sizeof(old_ss)))
		return -EFAULT;

	if (ret != 0)
		return ret;

	return 0;
}

static long syscall_epoll_create(struct thread_ctx *regs)
{
	return IS_ENABLED(CONFIG_EPOLL) ?
		epoll_create(regs->r[ARG_REG + 1]) :
		-ENOSYS;
}

static long syscall_epoll_ctl(struct thread_ctx *regs)
{
	long args[4] = {0};
	struct epoll_event evt;

	if (!IS_ENABLED(CONFIG_EPOLL))
		return -ENOSYS;

	if (copy_from_user(&args, (void *)regs->r[ARG_REG + 1], sizeof(args)))
		return -EFAULT;

	if ((args[1] != EPOLL_CTL_DEL) && copy_from_user(&evt,
			(void *)args[3], sizeof(evt)))
		return -EFAULT;

	return epoll_ctl(args[0], args[1], args[2], &evt);
}

static long syscall_epoll_wait(struct thread_ctx *regs)
{
	long args[4] = {0};

	if (!IS_ENABLED(CONFIG_EPOLL))
		return -ENOSYS;

	if (copy_from_user(&args, (void *)regs->r[ARG_REG + 1], sizeof(args)))
		return -EFAULT;

	if (args[2] <= 0 || args[2] > EPOLL_MAXEVENTS)
		return -EINVAL;

	if (!access_ok((void *)args[1], args[2] * sizeof(struct epoll_event)))
		return -EFAULT;

	return epoll_wait(args[0], (void *)args[1], args[2], args[3]);
}

static long syscall_get_funcname(struct thread_ctx *regs)
{
	unsigned long runaddr = regs->r[ARG_REG + 1];
	char *uname = (char *)regs->r[ARG_REG + 2], *name = NULL;
	unsigned long *uoffset = (void *)regs->r[ARG_REG + 3], offset = -1;

	name = (char *)elf_proc_funcname(current->proc, runaddr, &offset);
	if (name) {
		copy_to_user(uname, name, strlen(name) + 1);
		copy_to_user(uoffset, &offset, sizeof(offset));
		return 0;
	} else {
		return -ENOEXEC;
	}
}

static long syscall_set_config(struct thread_ctx *regs)
{
	char *config = (char *)regs->r[ARG_REG + 1];
	size_t size = regs->r[ARG_REG + 2];

	if (!current->proc->c->privilege)
		return -EACCES;

	if (!access_ok(config, size))
		return -EFAULT;

	return process_config_set(config, size, false);
}

static long syscall_get_property(struct thread_ctx *regs)
{
	unsigned long hdl = regs->r[ARG_REG + 1];
	void *nameoridx = (void *)regs->r[ARG_REG + 2];
	struct property *p = (void *)regs->r[ARG_REG + 3];
	char name[PROP_SIZE_MAX];

	if (!access_ok(p, sizeof(*p)))
		return -EFAULT;

	if ((unsigned long)nameoridx > PROP_NR_MAX) {
		if (strncpy_from_user(name, nameoridx, PROP_SIZE_MAX) < 0)
			return -EFAULT;

		return process_get_property(current->proc->c, hdl, name, p);
	}

	return process_get_property(current->proc->c, hdl, nameoridx, p);
}

static long syscall_get_proc_info(struct thread_ctx *regs)
{
	struct proc_info *uinfo = (void *)regs->r[ARG_REG + 1];

	if (!access_ok(uinfo, sizeof(*uinfo)))
		return -EFAULT;

	if (copy_to_user(&uinfo->gp, &current->proc->gp, sizeof(uinfo->gp)))
		return -EFAULT;

	if (copy_to_user(&uinfo->unwind, &current->proc->unwind, sizeof(uinfo->unwind)))
		return -EFAULT;

	return 0;
}

static long syscall_stat(struct thread_ctx *regs)
{
	return do_syscall_stat((const char *)regs->r[ARG_REG + 1],
		(struct stat *)regs->r[ARG_REG + 2]);
}

static long syscall_pread(struct thread_ctx *regs)
{
	long args[4] = {0};

	if (copy_from_user(args, (void *)regs->r[ARG_REG + 1],
		sizeof(args)))
		return -EFAULT;

	return do_syscall_pread(args[0], (void *)args[1],
		args[2], args[3]);
}

static long syscall_pwrite(struct thread_ctx *regs)
{
	long args[4] = {0};

	if (copy_from_user(args, (void *)regs->r[ARG_REG + 1],
		sizeof(args)))
		return -EFAULT;

	return do_syscall_pwrite(args[0], (const void *)args[1],
		args[2], args[3]);
}

static const syscall_fn syscall_routines[] = {
	syscall_sched_yield, /* SYSCALL_SCHED_YIELD */
	syscall_sched_suspend, /* SYSCALL_SCHED_SUSPEND */
	syscall_sigreturn,	 /* SYSCALL_SIGRETURN */
	syscall_pthread_exit,/* SYSCALL_PTHREAD_EXIT */
	syscall_exit,		/* SYSCALL_EXIT */
	NULL,				/* SYSCALL_RESERVED */

	syscall_open,		/* SYSCALL_OPEN */
	syscall_close,		/* SYSCALL_CLOSE */
	syscall_read,		/* SYSCALL_READ */
	syscall_write,		/* SYSCALL_WRITE */
	syscall_ioctl,		/* SYSCALL_IOCTL */
	syscall_sbrk,		/* SYSCALL_SBRK */
	syscall_mmap,		/* SYSCALL_MMAP */
	syscall_munmap,		/* SYSCALL_MUNMAP */
	syscall_poll,		/* SYSCALL_POLL */

	syscall_rename,		/* SYSCALL_RENAME */
	syscall_remove,		/* SYSCALL_REMOVE */
	syscall_lseek,		/* SYSCALL_LSEEK */
	syscall_fstat,		/* SYSCALL_FSTAT */
	syscall_stat,		/* SYSCALL_STAT */
	syscall_ftruncate,	/* SYSCALL_TRUNCATE */

	syscall_readdir,	/* SYSCALL_READDIR */
	syscall_mkdir,		/* SYSCALL_MKDIR */
	syscall_rmdir,		/* SYSCALL_RMDIR */

	syscall_execve,		/* SYSCALL_EXECVE */

	syscall_pread,		/* SYSCALL_PREAD */
	syscall_pwrite,		/* SYSCALL_PWRITE */

	syscall_sched_setscheduler,		/* SYSCALL_SCHED_SETSCHEDULER */
	syscall_sched_getscheduler,		/* SYSCALL_SCHED_GETSCHEDULER */
	syscall_sched_setparam,			/* SYSCALL_SCHED_SETPARAM */
	syscall_sched_getparam,			/* SYSCALL_SCHED_GETPARAM */
	syscall_sched_setaffinity,		/* SYSCALL_SCHED_SETAFFINITY */
	syscall_sched_getaffinity,		/* SYSCALL_SCHED_GETAFFINITY */
	syscall_sched_get_priority_max,	/* SYSCALL_SCHED_GET_PRIORITY_MAX */
	syscall_sched_get_priority_min,	/* SYSCALL_SCHED_GET_PRIORITY_MIN */

	syscall_usleep,				/* SYSCALL_USLEEP */
	syscall_msleep,				/* SYSCALL_MSLEEP */

	syscall_pthread_create,		/* SYSCALL_PTHREAD_CREATE */

	syscall_dup,				/* SYSCALL_DUP */
	syscall_dup2,				/* SYSCALL_DUP2 */

	syscall_wait_rdlock,		/* SYSCALL_WAIT_RDLOCK */
	syscall_wait_wrlock,		/* SYSCALL_WAIT_WRLOCK */
	syscall_wake_lock,			/* SYSCALL_WAKE_LOCK */
	syscall_wait,				/* SYSCALL_WAIT */
	syscall_wake,				/* SYSCALL_WAKE */

	syscall_clockgettime,		/* SYSCALL_CLOCKGETTIME */
	syscall_timer_create,		/* SYSCALL_TIMER_CREATE */
	syscall_timer_delete,		/* SYSCALL_TIMER_DELETE */
	syscall_timer_settime,		/* SYSCALL_TIMER_SETTIME */
	syscall_timer_gettime,		/* SYSCALL_TIMER_GETTIME */
	syscall_timer_getoverrun,	/* SYSCALL_TIMER_GETOVERRUN */
	syscall_clockgetres,		/* SYSCALL_CLOCKGETRES */

	syscall_pause,				/* SYSCALL_PAUSE */
	syscall_sigaction,			/* SYSCALL_SIGACTION */
	syscall_sigprocmask,		/* SYSCALL_SIGPROCMASK */
	syscall_sigqueue,			/* SYSCALL_SIGQUEUE */
	syscall_sigpending,			/* SYSCALL_SIGPENDING */
	syscall_sigtimedwait,		/* SYSCALL_SIGTIMEDWAIT */
	syscall_sigsuspend,			/* SYSCALL_SIGSUSPEND */
	syscall_sigaltstack,		/* SYSCALL_SIGALTSTACK */

	syscall_epoll_create,		/* SYSCALL_EPOLL_CREATE */
	syscall_epoll_ctl,			/* SYSCALL_EPOLL_CTL */
	syscall_epoll_wait,			/* SYSCALL_EPOLL_WAIT */

	syscall_select,				/* SYSCALL_SELECT */
	syscall_pselect,			/* SYSCALL_PSELECT */

	syscall_fcntl,				/* SYSCALL_FCNTL */
	syscall_pipe,				/* SYSCALL_PIPE */

	syscall_mq_open,			/* SYSCALL_MQ_OPEN */
	syscall_mq_unlink,			/* SYSCALL_MQ_UNLINK */
	syscall_mq_timedsend,		/* SYSCALL_MQ_TIMEDSEND */
	syscall_mq_timedreceive,	/* SYSCALL_MQ_TIMEDRECEIVE */
	syscall_mq_getsetattr,		/* SYSCALL_MQ_GETSETATTR */
	syscall_mq_notify,			/* SYSCALL_MQ_NOTIFY */
	syscall_mq_sendfd,			/* SYSCALL_MQ_SENDFD */
	syscall_mq_receivefd,		/* SYSCALL_MQ_RECEIVEFD */

	syscall_posix_spawn,		/* SYSCALL_POSIX_SPAWN */
	syscall_waitpid,			/* SYSCALL_WAITPID */
	syscall_eventfd2,			/* SYSCALL_EVENTFD2 */

	syscall_sem_init,			/* SYSCALL_SEM_INIT */
	syscall_sem_destroy,		/* SYSCALL_SEM_DESTROY */
	syscall_sem_post,			/* SYSCALL_SEM_POST */
	syscall_sem_wait,			/* SYSCALL_SEM_WAIT */
	syscall_sem_trywait,		/* SYSCALL_SEM_TRYWAIT */
	syscall_sem_timedwait,		/* SYSCALL_SEM_TIMEDWAIT */
	syscall_sem_getvalue,		/* SYSCALL_SEM_GETVALUE */
	syscall_sem_open,			/* SYSCALL_SEM_OPEN */
	syscall_sem_close,			/* SYSCALL_SEM_CLOSE */
	syscall_sem_unlink,			/* SYSCALL_SEM_UNLINK */

	syscall_set_config,			/* SYSCALL_SET_CONFIG */
	syscall_get_property,		/* SYSCALL_GET_PROPERTY */
	syscall_get_funcname,		/* SYSCALL_GET_FUNCNAME */
	syscall_get_proc_info,		/* SYSCALL_GET_PROC_INFO */
};

/*
 * SVC call handler (for user-thread only)
 * regs: Context registers
 */
__nosprot void *syscall_handler(struct thread_ctx *regs)
{
	unsigned long id = regs->r[ARG_REG];

	if (id >= ARRAY_SIZE(syscall_routines)) {
		EMSG("Invalid syscall %ld\n", id);
		regs->r[RET_REG] = -ENOENT;
		return regs;
	}

	/* handle the specific calls */
	if (id < SYSCALL_RESERVED)
		return (void *)syscall_routines[id](regs);

	local_irq_enable();
	regs->r[RET_REG] = syscall_routines[id](regs);
	local_irq_disable();

	if (thread_overflow(current)) {
		EMSG("oops-%s stack overflow\n", current->name);
		sched_exit(regs);
	}

	return regs;
}
