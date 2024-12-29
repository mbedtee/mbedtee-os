// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Reentrant stubs for the Newlib syscalls.
 * Newlib has been compiled with REENTRANT_SYSCALLS_PROVIDED.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <reent.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <sys/times.h>

#include <syscall.h>

#include <__pthread.h>

int _open_r(struct _reent *ptr,
	const char *name, int flags, int mode)
{
	int fd = -1;

	fd = syscall3(SYSCALL_OPEN, name, flags, mode);
	ptr->_errno = syscall_errno(fd);
	return syscall_retval(fd);
}

int _close_r(struct _reent *ptr, int fd)
{
	int ret = -1;

	if (fd >= 0)
		ret = syscall1(SYSCALL_CLOSE, fd);
	else
		ret = -EBADF;

	ptr->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

ssize_t _write_r(struct _reent *ptr, int fd,
	const void *buf, size_t cnt)
{
	ssize_t wr_bytes = 0;

	wr_bytes = syscall3(SYSCALL_WRITE, fd, buf, cnt);

	ptr->_errno = syscall_errno(wr_bytes);
	return syscall_retval(wr_bytes);
}

off_t _lseek_r(struct _reent *ptr, int fd, off_t offset, int flags)
{
	off_t local_offset = offset;

	if (syscall_stdfd(fd)) {
		ptr->_errno = 0;
		return offset;
	}

	local_offset = syscall3(SYSCALL_LSEEK, fd, offset, flags);

	ptr->_errno = syscall_errno(local_offset);
	return syscall_retval(local_offset);
}

ssize_t _read_r(struct _reent *ptr, int fd,
	void *buf, size_t cnt)
{
	ssize_t bytes_read = 0;

	if (cnt == 0) {
		ptr->_errno = 0;
		return 0;
	}

	bytes_read = syscall3(SYSCALL_READ, fd, buf, cnt);

	ptr->_errno = syscall_errno(bytes_read);
	return syscall_retval(bytes_read);
}

int _isatty_r(struct _reent *ptr, int fd)
{
	if (syscall_stdfd(fd)) {
		ptr->_errno = 0;
		return true;
	}

	return false;
}

void *_sbrk_r(struct _reent *ptr, ptrdiff_t incr)
{
	long ret = -1;

	ret = syscall1(SYSCALL_SBRK, incr);

	ptr->_errno = syscall_errno(ret);
	return (void *)syscall_retval(ret);
}

int _execve_r(struct _reent *ptr,
	const char *name, char * const *argv,
	char * const *env)
{
	long ret = -1;

	ret = syscall3(SYSCALL_EXECVE, name, argv, env);

	ptr->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int _fstat_r(struct _reent *ptr, int fd, struct stat *st)
{
	int ret = -1;

	if (syscall_stdfd(fd)) {
		st->st_mode = S_IFCHR;
		ptr->_errno = 0;
		return 0;
	}

	ret = syscall2(SYSCALL_FSTAT, fd, st);

	ptr->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int _stat_r(struct _reent *ptr, const char *path,
	struct stat *st)
{
	int fd = -1, ret = 0;

	fd = _open_r(ptr, path, O_RDONLY, 0);
	if (fd < 0)
		return fd;

	ret = _fstat_r(ptr, fd, st);

	_close_r(ptr, fd);
	return ret;
}

int _link_r(struct _reent *ptr,
	const char *old,
	const char *new)
{
	ptr->_errno = EMLINK;
	return -1;
}

int _unlink_r(struct _reent *ptr,
	const char *name)
{
	int ret = -1;

	ret = syscall1(SYSCALL_REMOVE, name);

	ptr->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

clock_t _times_r(struct _reent *ptr,
	struct tms *buf)
{
	ptr->_errno = ENOTSUP;
	return -1;
}

int _gettimeofday_r(struct _reent *ptr,
	struct timeval *tv, void *zone)
{
	int ret = -1;
	struct timespec ts;

	ret = syscall3(SYSCALL_CLOCKGETTIME, CLOCK_REALTIME, &ts, zone);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;

	ptr->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int _getentropy_r(struct _reent *ptr,
	void *buf, size_t buflen)
{
	int r = 0;

	while (buflen >= sizeof(r)) {
		r = rand();
		memcpy(buf, &r, sizeof(r));
		buflen -= sizeof(r);
		buf += sizeof(r);
	}

	if (buflen > 0) {
		r = rand();
		memcpy(buf, &r, buflen);
	}

	ptr->_errno = 0;

	return 0;
}

int _rename_r(struct _reent *ptr,
	const char *oldpath,
	const char *newpath)
{
	int ret = -1;

	ret = syscall2(SYSCALL_RENAME, oldpath, newpath);
	ptr->_errno = syscall_errno(ret);

	return syscall_retval(ret);
}

int _fork_r(struct _reent *ptr)
{
	ptr->_errno = ENOTSUP;
	return -1;
}

int _wait_r(struct _reent *ptr, int *status)
{
	ptr->_errno = ECHILD;
	return -1;
}

pid_t _getpid_r(struct _reent *ptr)
{
	ptr->_errno = 0;
	return __pthread_self->proc->id;
}

__weak_symbol int access(const char *fpath, int mode)
{
	struct stat s;

	if (mode & X_OK)
		return -1;

	if (stat(fpath, &s))
		return -1;

	if (s.st_mode & S_IFDIR)
		return 0;

	if ((mode & W_OK) && !(s.st_mode & S_IWRITE))
		return -1;

	return 0;
}

__weak_symbol int creat(const char *path, mode_t mode)
{
	return open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

__weak_symbol int ftruncate(int fd, off_t length)
{
	int ret = -1;

	ret = syscall2(SYSCALL_TRUNCATE, fd, length);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

pid_t gettid(void)
{
	return __pthread_self->id;
}

/*
 * System's thread ID MAX (threads-max limitation)
 */
pid_t gettid_max(void)
{
	return __pthread_self->idmax;
}
