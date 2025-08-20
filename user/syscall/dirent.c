// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * directory operations
 */

#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <syscall.h>
#include <sys/lock.h>

#define DIR_BUF_SIZE 1024

static int __readdir(int fd, void *buf, size_t cnt)
{
	int ret = -1;

	ret = syscall3(SYSCALL_READDIR, fd, buf, cnt);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

static void __seekdir(int fd, long pos)
{
	int ret = -1;

	ret = syscall3(SYSCALL_LSEEK, fd, pos, SEEK_SET);
	errno = syscall_errno(ret);
}

DIR *opendir(const char *name)
{
	int fd = -1;
	DIR *d = NULL;

	fd = open(name, O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		return NULL;

	d = malloc(DIR_BUF_SIZE);
	if (!d) {
		close(fd);
		errno = ENOMEM;
		return NULL;
	}

	d->dd_fd = fd;
	d->dd_buf = (char *)(d + 1);
	d->dd_len = DIR_BUF_SIZE - sizeof(DIR);
	d->dd_loc = 0;
	d->dd_size = 0;
	d->dd_off = 0;
	__lock_init_recursive(d->dd_lock);
	return d;
}

int closedir(DIR *d)
{
	int ret = -1;

	if (d) {
		__lock_acquire_recursive(d->dd_lock);
		ret = close(d->dd_fd);
		__lock_release_recursive(d->dd_lock);
		__lock_close_recursive(d->dd_lock);
		free(d);
	} else {
		errno = EINVAL;
	}

	return ret;
}

struct dirent *readdir(DIR *d)
{
	struct dirent *ptr = NULL;

	__lock_acquire_recursive(d->dd_lock);

	if (d->dd_loc >= d->dd_size) {
		d->dd_loc = 0;
		d->dd_size = 0;
	}

	if (d->dd_loc == 0) {
		d->dd_size = __readdir(d->dd_fd, d->dd_buf, d->dd_len);
		if (d->dd_size <= 0)
			goto out;
	}

	ptr = (struct dirent *)(d->dd_buf + d->dd_loc);
	if (ptr->d_reclen == 0 || ptr->d_reclen > (d->dd_size - d->dd_loc)) {
		d->dd_loc = 0;
		d->dd_size = 0;
		ptr = NULL;
		goto out;
	}
	d->dd_loc += ptr->d_reclen;
	d->dd_off = ptr->d_off;

out:
	__lock_release_recursive(d->dd_lock);
	return ptr;
}

int mkdir(const char *dirname, mode_t mode)
{
	int ret = -1;

	ret = syscall2(SYSCALL_MKDIR, dirname, mode);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int rmdir(const char *dirname)
{
	int ret = -1;

	ret = syscall1(SYSCALL_RMDIR, dirname);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

void seekdir(DIR *d, long off)
{
	__lock_acquire_recursive(d->dd_lock);

	__seekdir(d->dd_fd, off);

	d->dd_loc = 0;
	d->dd_size = 0;
	d->dd_off = off;

	__lock_release_recursive(d->dd_lock);
}

void rewinddir(DIR *d)
{
	seekdir(d, 0);
}

long telldir(DIR *d)
{
	return d->dd_off;
}
