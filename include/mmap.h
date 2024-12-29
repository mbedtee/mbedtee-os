/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * mmap() and munmap()
 */

#ifndef _MMAP_H
#define _MMAP_H

#include <sys/types.h>

#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */

#define MAP_SHARED  0x1		/* Share this mapping. */
#define MAP_PRIVATE 0x2		/* Create a private copy-on-write mapping. */

#define MAP_FAILED	((void *) -1)

void *mmap(void *addr, size_t length, int prot, int flags,
			int fd, off_t offset);

/*
 * unlike the posix complex definition which support to unmap
 * separated pieces (addr/length) within the mapped region
 *
 * this function unmaps the whole mapped region in one syscall,
 * addr must be the mmap() return address, length is ignored
 */
int munmap(void *addr, size_t length);

int shm_open(const char *name, int oflag, mode_t mode);
int shm_unlink(const char *name);

#endif
