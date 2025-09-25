// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * POSIX semaphore userland wrappers
 */

#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <syscall.h>

int sem_init(sem_t *sem, int pshared, unsigned int value)
{
	long ret = syscall3(SYSCALL_SEM_INIT, sem, pshared, value);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sem_destroy(sem_t *sem)
{
	long ret = syscall1(SYSCALL_SEM_DESTROY, sem);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sem_post(sem_t *sem)
{
	long ret = syscall1(SYSCALL_SEM_POST, sem);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sem_wait(sem_t *sem)
{
	long ret = syscall1(SYSCALL_SEM_WAIT, sem);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sem_trywait(sem_t *sem)
{
	long ret = syscall1(SYSCALL_SEM_TRYWAIT, sem);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout)
{
	long ret = syscall2(SYSCALL_SEM_TIMEDWAIT, sem, abs_timeout);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sem_getvalue(sem_t *sem, int *sval)
{
	long ret = syscall2(SYSCALL_SEM_GETVALUE, sem, sval);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

sem_t *sem_open(const char *name, int oflag, ...)
{
	mode_t mode = 0;
	unsigned int value = 0;
	va_list ap;
	sem_t *sem = NULL;
	long ret = -1;
	const char *p = NULL;

	if (!name || name[0] != '/' || name[1] == '\0') {
		errno = EINVAL;
		return SEM_FAILED;
	}

	p = name + 1;

	if (oflag & O_CREAT) {
		va_start(ap, oflag);
		mode = va_arg(ap, mode_t);
		value = va_arg(ap, unsigned int);
		va_end(ap);
	}

	sem = malloc(sizeof(*sem));
	if (!sem) {
		errno = ENOMEM;
		return SEM_FAILED;
	}
	memset(sem, 0, sizeof(*sem));

	/* glibc style: pass name+1 to kernel */
	ret = syscall5(SYSCALL_SEM_OPEN, p, oflag, mode, value, sem);
	errno = syscall_errno(ret);
	if (syscall_retval(ret) < 0) {
		free(sem);
		return SEM_FAILED;
	}

	return sem;
}

int sem_close(sem_t *sem)
{
	long ret = -1;
	int err = 0;
	int rv = -1;

	if (!sem || sem == SEM_FAILED) {
		errno = EINVAL;
		return -1;
	}

	ret = syscall1(SYSCALL_SEM_CLOSE, sem);
	err = syscall_errno(ret);
	rv = syscall_retval(ret);
	if (rv == 0)
		free(sem);
	errno = err;
	return rv;
}

int sem_unlink(const char *name)
{
	long ret = -1;

	if (!name || name[0] != '/' || name[1] == '\0') {
		errno = EINVAL;
		return -1;
	}

	ret = syscall1(SYSCALL_SEM_UNLINK, name + 1);
	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
