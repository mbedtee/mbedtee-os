// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Shared Memory Open/Unlink
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mmap.h>

#include <sys/syslimits.h>

#include <syscall.h>

int shm_open(const char *name, int oflag, mode_t mode)
{
	char shm_name[NAME_MAX + 6] = "/shm/";
	size_t namelen = 0;

	while (*name == '/')
		++name;

	namelen = strlen(name) + 1;
	if (namelen >= NAME_MAX || namelen <= 1) {
		errno = EINVAL;
		return -1;
	}

	strlcpy(shm_name + 5, name, NAME_MAX);

	return open(shm_name, oflag, mode);
}

int shm_unlink(const char *name)
{
	char shm_name[NAME_MAX + 6] = "/shm/";
	size_t namelen = 0;

	while (*name == '/')
		++name;

	namelen = strlen(name) + 1;
	if (namelen >= NAME_MAX || namelen <= 1) {
		errno = EINVAL;
		return -1;
	}

	strlcpy(shm_name + 5, name, NAME_MAX);

	return unlink(shm_name);
}
