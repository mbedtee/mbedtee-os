/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * eventfd() userspace API
 */

#ifndef _EVENTFD_H
#define _EVENTFD_H

#include <stdint.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t eventfd_t;

/* Linux-compatible flags (ABI values passed to the syscall) */
#define EFD_SEMAPHORE  (1u << 0)
#define EFD_NONBLOCK   (1u << 11)
#define EFD_CLOEXEC    (1u << 19)

int eventfd(unsigned int initval, int flags);

int eventfd_read(int fd, eventfd_t *value);

int eventfd_write(int fd, eventfd_t value);

#ifdef __cplusplus
}
#endif

#endif
