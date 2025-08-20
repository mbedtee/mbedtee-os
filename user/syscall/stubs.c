// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Reentrant stubs for the Newlib syscalls.
 * Newlib has been compiled with REENTRANT_SYSCALLS_PROVIDED.
 */

#include <string.h>
#include <reent.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>

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

ssize_t pwrite(int fd, const void *buf, size_t cnt, off_t offset)
{
	ssize_t ret = 0;

	ret = syscall4(SYSCALL_PWRITE, fd, buf, cnt, offset);

	_REENT->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

ssize_t pread(int fd, void *buf, size_t cnt, off_t offset)
{
	ssize_t ret = 0;

	if (cnt == 0) {
		_REENT->_errno = 0;
		return 0;
	}

	ret = syscall4(SYSCALL_PREAD, fd, buf, cnt, offset);

	_REENT->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int _isatty_r(struct _reent *ptr, int fd)
{
	struct stat st;
	int ret = -1;

	ret = syscall2(SYSCALL_FSTAT, fd, &st);
	if (ret < 0) {
		if (syscall_stdfd(fd)) {
			ptr->_errno = 0;
			return 1;
		}
		ptr->_errno = syscall_errno(ret);
		return 0;
	}

	if (S_ISCHR(st.st_mode)) {
		ptr->_errno = 0;
		return 1;
	}

	ptr->_errno = ENOTTY;
	return 0;
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

	ret = syscall2(SYSCALL_FSTAT, fd, st);
	if (ret >= 0) {
		ptr->_errno = 0;
		return ret;
	}

	/*
	 * Legacy fallback: if the kernel does not support fstat for
	 * standard fds, assume a character device.
	 */
	if (syscall_stdfd(fd) && (syscall_errno(ret) == ENOSYS ||
		syscall_errno(ret) == ENOTSUP)) {
		st->st_mode = S_IFCHR;
		ptr->_errno = 0;
		return 0;
	}

	ptr->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int _stat_r(struct _reent *ptr, const char *path,
	struct stat *st)
{
	int ret = -1;

	ret = syscall2(SYSCALL_STAT, path, st);

	ptr->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int _lstat_r(struct _reent *ptr, const char *path,
	struct stat *st)
{
	/* No symlink support: lstat behaves like stat. */
	return _stat_r(ptr, path, st);
}

int lstat(const char *path, struct stat *st)
{
	return _lstat_r(_REENT, path, st);
}

int _link_r(struct _reent *ptr,
	const char *old,
	const char *new)
{
	ptr->_errno = EMLINK;
	return -1;
}

int _fcntl_r(struct _reent *ptr, int fd, int cmd, int arg)
{
	long ret = -1;

	ret = syscall3(SYSCALL_FCNTL, fd, cmd, arg);
	ptr->_errno = syscall_errno(ret);
	return syscall_retval(ret);
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
	struct timespec ts;
	int ret = -1;

	if (!buf) {
		ptr->_errno = EFAULT;
		return (clock_t)-1;
	}

	memset(buf, 0, sizeof(*buf));

	ret = syscall3(SYSCALL_CLOCKGETTIME,
		CLOCK_PROCESS_CPUTIME_ID, &ts, NULL);
	if (syscall_retval(ret) == 0) {
		/* Report all CPU time as user time */
		buf->tms_utime = ts.tv_sec * CLOCKS_PER_SEC +
			ts.tv_nsec / (1000000000 / CLOCKS_PER_SEC);
	}

	/* Return monotonic clock ticks */
	ret = syscall3(SYSCALL_CLOCKGETTIME,
		CLOCK_MONOTONIC, &ts, NULL);
	if (syscall_retval(ret) != 0) {
		ptr->_errno = syscall_errno(ret);
		return (clock_t)-1;
	}

	ptr->_errno = 0;
	return ts.tv_sec * CLOCKS_PER_SEC +
		ts.tv_nsec / (1000000000 / CLOCKS_PER_SEC);
}

int _gettimeofday_r(struct _reent *ptr,
	struct timeval *tv, void *zone)
{
	int ret = -1;
	struct timespec ts;

	ret = syscall3(SYSCALL_CLOCKGETTIME, CLOCK_REALTIME, &ts, zone);

	ptr->_errno = syscall_errno(ret);

	if (syscall_retval(ret) == 0) {
		tv->tv_sec = ts.tv_sec;
		tv->tv_usec = ts.tv_nsec / 1000;
	}

	return syscall_retval(ret);
}

int _getentropy_r(struct _reent *ptr,
	void *buf, size_t buflen)
{
	static int urandom_fd = -1;
	int expected = -1;
	ssize_t ret = 0;
	int fd = __atomic_load_n(&urandom_fd, __ATOMIC_ACQUIRE);

	if (fd < 0) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			ptr->_errno = ENOSYS;
			return -1;
		}
		if (!__atomic_compare_exchange_n(&urandom_fd, &expected,
			fd, false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
			close(fd);
			fd = expected;
		}
	}

	ret = read(fd, buf, buflen);
	if (ret < 0 || (size_t)ret != buflen) {
		ptr->_errno = errno;
		return -1;
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
	return pid_of(__pthread_self->pthread);
}

__weak_symbol int access(const char *fpath, int mode)
{
	struct stat s;

	if (mode & X_OK) {
		errno = EACCES;
		return -1;
	}

	/*
	 * mbedtee has no file permission model -- every existing file
	 * is readable and writable.  Only check existence via stat().
	 */
	if (stat(fpath, &s))
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

__weak_symbol int fsync(int fd)
{
	errno = ENOTSUP;
	return -1;
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
