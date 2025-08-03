// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * directory operations for kernel space
 */

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <kmalloc.h>
#include <file.h>

static int __opendir(const char *dirname)
{
	return sys_open(dirname, O_RDONLY | O_DIRECTORY);
}

static int __closedir(int fd)
{
	return sys_close(fd);
}

static int __readdir(int fd, void *buf, size_t cnt)
{
	return sys_readdir(fd, buf, cnt);
}

static int __seekdir(int fd, long pos)
{
	return sys_lseek(fd, pos, SEEK_SET);
}

DIR *opendir(const char *name)
{
	int fd = -1;
	DIR *d = NULL;

	fd = __opendir(name);
	if (fd < 0)
		return NULL;

	d = kmalloc(1024);
	if (!d) {
		__closedir(fd);
		return NULL;
	}

	d->dd_fd = fd;
	d->dd_buf = (char *)(d + 1);
	d->dd_len = 1024 - sizeof(DIR);
	d->dd_loc = 0;
	d->dd_size = 0;
	d->dd_off = 0;
	return d;
}

int closedir(DIR *d)
{
	int ret = -1;

	if (d) {
		ret = __closedir(d->dd_fd);
		kfree(d);
	}

	return ret;
}

struct dirent *readdir(DIR *d)
{
	struct dirent *ptr = NULL;

	if (!d)
		return NULL;

	if (d->dd_loc >= d->dd_size) {
		d->dd_loc = 0;
		d->dd_size = 0;
	}

	if (d->dd_loc == 0) {
		d->dd_size = __readdir(d->dd_fd, d->dd_buf, d->dd_len);
		if (d->dd_size <= 0)
			return NULL;
	}

	ptr = (struct dirent *)(d->dd_buf + d->dd_loc);
	if (ptr->d_reclen == 0 || ptr->d_reclen > (d->dd_size - d->dd_loc)) {
		d->dd_loc = 0;
		d->dd_size = 0;
		return NULL;
	}
	d->dd_loc += ptr->d_reclen;
	d->dd_off = ptr->d_off;

	return ptr;
}

void seekdir(DIR *d, long off)
{
	if (!d)
		return;

	__seekdir(d->dd_fd, off);

	d->dd_loc = 0;
	d->dd_size = 0;
	d->dd_off = off;
}

void rewinddir(DIR *d)
{
	seekdir(d, 0);
}

long telldir(DIR *d)
{
	return d ? d->dd_off : -1;
}
