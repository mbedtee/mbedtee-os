// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * newlib stub functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <file.h>
#include <trace.h>
#include <thread.h>
#include <kmalloc.h>
#include <ksignal.h>

#define _errno(x)    ((((x) >= 0) || ((x) < -__ELASTERROR)) ? 0 : (-(x)))
#define _retval(x)   ((((x) >= 0) || ((x) < -__ELASTERROR)) ? (x) : (-1))

__weak_symbol int pthread_setcancelstate(int state, int *old_state)
{
	return 0;
}

__weak_symbol int _isatty_r(struct _reent *ptr, int fd)
{
	ptr->_errno = 0;
	return true;
}

__weak_symbol int _fstat_r(struct _reent *ptr, int fd, struct stat *st)
{
	int ret = sys_fstat(fd, st);

	ptr->_errno = _errno(ret);
	return _retval(ret);
}

__weak_symbol off_t _lseek_r(struct _reent *ptr, int fd, off_t offset, int flags)
{
	off_t ret = sys_lseek(fd, offset, flags);

	ptr->_errno = _errno(ret);
	return _retval(ret);
}

__weak_symbol ssize_t _read_r(struct _reent *ptr, int fd,
	void *buf, size_t cnt)
{
	ssize_t ret = sys_read(fd, buf, cnt);

	ptr->_errno = _errno(ret);
	return _retval(ret);
}

__weak_symbol int _close_r(struct _reent *ptr, int fd)
{
	int ret = sys_close(fd);

	ptr->_errno = _errno(ret);
	return _retval(ret);
}

__weak_symbol ssize_t _write_r(struct _reent *ptr, int fd,
	const void *buf, size_t cnt)
{
	ssize_t ret = sys_write(fd, buf, cnt);

	ptr->_errno = _errno(ret);
	return _retval(ret);
}

__weak_symbol void *_malloc_r(struct _reent *ptr, size_t cnt)
{
	ptr->_errno = 0;
	return kmalloc(cnt);
}

__weak_symbol void _free_r(struct _reent *ptr, void *buf)
{
	ptr->_errno = 0;
	kfree(buf);
}

__weak_symbol void *_calloc_r(struct _reent *ptr, size_t n, size_t size)
{
	ptr->_errno = 0;
	return kcalloc(n, size);
}

__weak_symbol void *_realloc_r(struct _reent *ptr, void *old, size_t size)
{
	ptr->_errno = 0;
	return krealloc(old, size);
}

__weak_symbol int _getentropy_r(struct _reent *ptr,
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

__weak_symbol int _kill_r(struct _reent *ptr, int tid, int signo)
{
	IMSG("Newlib raising %d @ %04d\n", signo, tid);

	int ret = sigenqueue(tid, signo, SI_QUEUE,
			 (union sigval)((void *)-ESRCH), true);

	if (ret != 0)
		abort();

	return ret;
}

/*
 * newlib-specific static locks
 */
struct __lock {struct mutex m; };

#define DECLARE_DEFAULT_NEWLIB_MUTEX(name) \
	struct __lock name = {.m = DEFAULT_MUTEX(name.m)}
#define DECLARE_RECURSIVE_NEWLIB_MUTEX(name) \
	struct __lock name = {.m = RECURSIVE_MUTEX(name.m)}

DECLARE_RECURSIVE_NEWLIB_MUTEX(__lock___sinit_recursive_mutex);
DECLARE_RECURSIVE_NEWLIB_MUTEX(__lock___sfp_recursive_mutex);
DECLARE_RECURSIVE_NEWLIB_MUTEX(__lock___atexit_recursive_mutex);
DECLARE_RECURSIVE_NEWLIB_MUTEX(__lock___malloc_recursive_mutex);
DECLARE_RECURSIVE_NEWLIB_MUTEX(__lock___env_recursive_mutex);
DECLARE_RECURSIVE_NEWLIB_MUTEX(__lock___at_quick_exit_mutex);
DECLARE_DEFAULT_NEWLIB_MUTEX(__lock___tz_mutex);
DECLARE_DEFAULT_NEWLIB_MUTEX(__lock___dd_hash_mutex);
DECLARE_DEFAULT_NEWLIB_MUTEX(__lock___arc4random_mutex);

void __retarget_lock_init(_LOCK_T *l)
{
	struct __lock *__l = NULL;

	__l = kmalloc(sizeof(struct __lock));

	if (__l) {
		mutex_init(&__l->m);
		*l = __l;
	}
}

void __retarget_lock_init_recursive(_LOCK_T *l)
{
	struct __lock *__l = NULL;

	__l = kmalloc(sizeof(struct __lock));

	if (__l) {
		mutex_init_recursive(&__l->m);
		*l = __l;
	}
}

void __retarget_lock_close(_LOCK_T l)
{
	kfree(l);
}

void __retarget_lock_close_recursive(_LOCK_T l)
{
	kfree(l);
}

void __retarget_lock_acquire(_LOCK_T l)
{
	mutex_lock(&l->m);
}

void __retarget_lock_acquire_recursive(_LOCK_T l)
{
	mutex_lock(&l->m);
}

int __retarget_lock_try_acquire(_LOCK_T l)
{
	return mutex_trylock(&l->m) ? 0 : EBUSY;
}

int __retarget_lock_try_acquire_recursive(_LOCK_T l)
{
	return mutex_trylock(&l->m) ? 0 : EBUSY;
}

void __retarget_lock_release(_LOCK_T l)
{
	mutex_unlock(&l->m);
}

void __retarget_lock_release_recursive(_LOCK_T l)
{
	mutex_unlock(&l->m);
}
