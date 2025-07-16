/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * POSIX semaphore API
 */

#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* sem_t contains an opaque kernel handle. */
typedef struct {
	uintptr_t __ksem;
} sem_t;

/*
 * Max length of the user-visible semaphore name (excluding the internal "/sema"
 * prefix used by the kernel/VFS namespace).
 */
#ifndef SEM_NAME_MAX
#define SEM_NAME_MAX 64
#endif

#if !defined(SEM_VALUE_MAX)
#define SEM_VALUE_MAX 0x7fffffffU
#endif

int sem_init(sem_t *sem, int pshared, unsigned int value);
int sem_destroy(sem_t *sem);

int sem_post(sem_t *sem);

int sem_wait(sem_t *sem);
int sem_trywait(sem_t *sem);
int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout);

int sem_getvalue(sem_t *sem, int *sval);

#if !defined(SEM_FAILED)
#define SEM_FAILED ((sem_t *)-1)
#endif

sem_t *sem_open(const char *name, int oflag, ...);
int sem_close(sem_t *sem);
int sem_unlink(const char *name);

#ifdef __cplusplus
}
#endif

#endif
