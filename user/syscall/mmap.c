// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * mmap() and munmap()
 */

#include <mmap.h>
#include <syscall.h>

void *mmap(void *addr, size_t length, int prot,
			int flags, int fd, off_t offset)
{
	long ret = -1;

	ret = syscall6(SYSCALL_MMAP, addr, length, prot,
				flags, fd, offset);

	errno = syscall_errno(ret);
	return (void *)syscall_retval(ret);
}

int munmap(void *addr, size_t length)
{
	int ret = -1;

	if (!addr || addr == MAP_FAILED) {
		errno = EINVAL;
		return -1;
	}

	ret = syscall2(SYSCALL_MUNMAP, addr, length);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
