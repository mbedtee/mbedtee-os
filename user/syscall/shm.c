// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Shared Memory Open/Unlink
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mmap.h>

#include <sys/syslimits.h>

#include <syscall.h>

static int shm_build_name(const char *name, char *buf)
{
	size_t namelen = 0;

	if (!name) {
		errno = EINVAL;
		return -1;
	}

	while (*name == '/')
		++name;

	namelen = strlen(name) + 1;
	if (namelen >= NAME_MAX || namelen <= 1) {
		errno = EINVAL;
		return -1;
	}

	memcpy(buf, "/shm/", 5);
	strlcpy(buf + 5, name, NAME_MAX);
	return 0;
}

int shm_open(const char *name, int oflag, mode_t mode)
{
	char shm_name[NAME_MAX + 6];

	if (shm_build_name(name, shm_name) < 0)
		return -1;

	return open(shm_name, oflag, mode);
}

int shm_unlink(const char *name)
{
	char shm_name[NAME_MAX + 6];

	if (shm_build_name(name, shm_name) < 0)
		return -1;

	return unlink(shm_name);
}
