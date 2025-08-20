// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * simple shell @ user-space
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdarg.h>
#include <utrace.h>
#include <pthread.h>
#include <poll.h>

#include <shell.h>

/* Implementation of shell abstraction layer for user space */

void *shell_malloc(size_t size)
{
	return malloc(size);
}

void *shell_calloc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

void shell_free(void *ptr)
{
	free(ptr);
}

int shell_thread_create(shell_tid_t *out,
	shell_thread_entry_t entry, void *arg)
{
	pthread_t tid;
	int ret = 0;

	ret = pthread_create(&tid, NULL, (void *)entry, arg);
	if (ret != 0)
		return -ret;

	*out = (shell_tid_t)tid;
	return 0;
}

int shell_thread_join(shell_tid_t t)
{
	int ret = 0;
	pthread_t tid;

	if (t == 0)
		return -EINVAL;

	tid = (pthread_t)t;

	ret = pthread_join(tid, NULL);
	return ret ? -ret : 0;
}

int shell_thread_detach(shell_tid_t t)
{
	int ret = 0;
	pthread_t tid;

	if (t == 0)
		return -EINVAL;

	tid = (pthread_t)t;

	ret = pthread_detach(tid);
	return ret ? -ret : 0;
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

	return open(path, flags, mode);
}

int shell_close(int fd)
{
	return close(fd);
}

ssize_t shell_read(int fd, void *buf, size_t count)
{
	return read(fd, buf, count);
}

ssize_t shell_write(int fd, const void *buf, size_t count)
{
	return write(fd, buf, count);
}

off_t shell_lseek(int fd, off_t offset, int whence)
{
	return lseek(fd, offset, whence);
}

int shell_fstat(int fd, struct stat *statbuf)
{
	return fstat(fd, statbuf);
}

int shell_mkdir(const char *path, mode_t mode)
{
	return mkdir(path, mode);
}

int shell_unlink(const char *path)
{
	return unlink(path);
}

int shell_rmdir(const char *path)
{
	return rmdir(path);
}

int shell_rename(const char *oldpath, const char *newpath)
{
	int ret = rename(oldpath, newpath);

	return ret < 0 ? -errno : ret;
}

int shell_creat(const char *path, mode_t mode)
{
	return creat(path, mode);
}

int shell_pipe(int pipefd[2])
{
	return pipe(pipefd);
}

int shell_dup(int oldfd)
{
	return dup(oldfd);
}

int shell_fcntl(int fd, int cmd, unsigned long arg)
{
	int ret = fcntl(fd, cmd, arg);
	return ret < 0 ? -errno : ret;
}

pid_t shell_get_pid(void)
{
	return getpid();
}

pid_t shell_get_tid(void)
{
	return gettid();
}

pid_t shell_get_tid_max(void)
{
	return gettid_max();
}

int shell_kill(pid_t pid, int sig)
{
	return kill(pid, sig);
}

int shell_tkill(pid_t tid, int sig)
{
	return pthread_kill(tid, sig);
}

int shell_spawn(pid_t *pid, const posix_spawn_file_actions_t *file_actions,
	char *const argv[])
{
	int ret = 0;

	ret = posix_spawnp(pid, argv[0], file_actions, NULL, argv, NULL);
	return ret == 0 ? 0 : -ret;
}

int shell_waitpid(pid_t pid, int *status, int options)
{
	pid_t r;

	r = waitpid(pid, status, options);
	if (r < 0)
		return -errno;
	return 0;
}

pid_t shell_waitpid_raw(pid_t pid, int *status, int options)
{
	pid_t r;

	r = waitpid(pid, status, options);
	if (r < 0)
		return -errno;
	return r;
}

void shell_time2date(time_t time, struct tm *tm)
{
	localtime_r(&time, tm);
}

int shell_get_monotonic(struct timespec *ts)
{
	return clock_gettime(CLOCK_MONOTONIC, ts);
}

int shell_get_realtime(struct timespec *ts)
{
	return clock_gettime(CLOCK_REALTIME, ts);
}

int main(void)
{
	struct sched_param p;

	p.sched_priority = 62; /* mbedtee max - 1 */
	sched_setscheduler(0, SCHED_FIFO, &p);

	shell_entry();

	return -ENOTTY;
}
