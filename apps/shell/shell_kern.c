// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * simple shell @ kern-space
 */

#include <fs.h>
#include <stdarg.h>
#include <strmisc.h>
#include <trace.h>
#include <file.h>
#include <timer.h>
#include <ktime.h>
#include <thread.h>
#include <kmalloc.h>
#include <kthread.h>
#include <dirent.h>

#include <sys/waitpid.h>
#include <sys/spawn.h>
#include <shell.h>

/* Implementation of shell abstraction layer for kernel space */

void *shell_malloc(size_t size)
{
	return kmalloc(size);
}

void *shell_calloc(size_t nmemb, size_t size)
{
	return kcalloc(nmemb, size);
}

void shell_free(void *ptr)
{
	kfree(ptr);
}

int shell_thread_create(shell_tid_t *out,
	shell_thread_entry_t entry, void *arg)
{
	int tid;

	tid = kthread_run(entry, arg, "kshell");
	if (tid < 0)
		return tid;

	*out = tid;
	return 0;
}

int shell_thread_join(shell_tid_t t)
{
	struct thread *th;
	pid_t tid;

	if (t == 0)
		return -EINVAL;

	tid = (pid_t)t;
	th = thread_get(tid);
	if (!th)
		return -ESRCH;

	/* join_q is already part of struct thread; wakeup happens on exit */
	wait(&th->join_q);

	thread_put(th);

	return 0;
}

int shell_thread_detach(shell_tid_t t)
{
	pid_t tid;
	struct thread *th;

	if (t == 0)
		return -EINVAL;

	tid = (pid_t)t;
	th = thread_get(tid);
	if (!th)
		return -ESRCH;

	/* kthread resources are reclaimed on exit when no references remain */

	thread_put(th);
	return 0;
}

int shell_open(const char *path, int flags, ...)
{
	mode_t mode = 0;

	if (flags & O_CREAT) {
		va_list ap;

		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	return sys_open(path, flags, mode);
}

int shell_close(int fd)
{
	return sys_close(fd);
}

ssize_t shell_read(int fd, void *buf, size_t count)
{
	return sys_read(fd, buf, count);
}

ssize_t shell_write(int fd, const void *buf, size_t count)
{
	return sys_write(fd, buf, count);
}

off_t shell_lseek(int fd, off_t offset, int whence)
{
	return sys_lseek(fd, offset, whence);
}

int shell_fstat(int fd, struct stat *statbuf)
{
	return sys_fstat(fd, statbuf);
}

int shell_mkdir(const char *path, mode_t mode)
{
	return sys_mkdir(path, mode);
}

int shell_unlink(const char *path)
{
	return sys_unlink(path);
}

int shell_rmdir(const char *path)
{
	return sys_rmdir(path);
}

int shell_rename(const char *oldpath, const char *newpath)
{
	return sys_rename(oldpath, newpath);
}

int shell_creat(const char *path, mode_t mode)
{
	return sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

int shell_pipe(int pipefd[2])
{
	return sys_pipe(pipefd);
}

int shell_dup(int oldfd)
{
	return sys_dup(oldfd);
}

int shell_fcntl(int fd, int cmd, unsigned long arg)
{
	return sys_fcntl(fd, cmd, arg);
}

pid_t shell_get_pid(void)
{
	return current->proc->id;
}

pid_t shell_get_tid(void)
{
	return current_id;
}

pid_t shell_get_tid_max(void)
{
	return sched_idx_max;
}

int shell_kill(pid_t pid, int sig)
{
	return sigenqueue(pid, sig, SI_USER, (union sigval)(0), false);
}

int shell_tkill(pid_t tid, int sig)
{
	return sigenqueue(tid, sig, SI_USER, (union sigval)(0), true);
}

int shell_spawn(pid_t *pid, const posix_spawn_file_actions_t *file_actions,
	char *const argv[])
{
	return kposix_spawn(pid, argv[0], file_actions, argv);
}

int shell_waitpid(pid_t pid, int *status, int options)
{
	pid_t r;

	r = kwaitpid(pid, status, options);
	if (r < 0)
		return r;

	return 0;
}

pid_t shell_waitpid_raw(pid_t pid, int *status, int options)
{
	return kwaitpid(pid, status, options);
}

void shell_time2date(time_t time, struct tm *tm)
{
	time2date(time, tm);
}

int shell_get_monotonic(struct timespec *ts)
{
	return clock_gettime(CLOCK_MONOTONIC, ts);
}

int shell_get_realtime(struct timespec *ts)
{
	return clock_gettime(CLOCK_REALTIME, ts);
}

long shell_kthread(void *data)
{
	struct sched_param p = {.sched_priority =
		SCHED_PRIO_MAX - 1};

	sched_setscheduler(0, SCHED_FIFO, &p);

	shell_entry();

	return -ENOTTY;
}
