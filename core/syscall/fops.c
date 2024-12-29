// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * file operations @ syscall layer
 */

#include <errno.h>
#include <trace.h>
#include <device.h>
#include <thread.h>
#include <strmisc.h>
#include <fs.h>
#include <sched.h>
#include <kmalloc.h>
#include <file.h>
#include <uaccess.h>
#include <poll.h>

#include "fops.h"

/*
 * allocate the entry path inside the parent FS
 */
int alloc_path(const char *src, struct file_path *p)
{
	int ret = -EACCES;
	struct file_system *fs = NULL;
	char ori[FS_PATH_MAX];

	ret = strncpy_from_user(ori, src, FS_PATH_MAX);
	if (ret < 0)
		return ret;

	if (ret == FS_PATH_MAX)
		return -ENAMETOOLONG;

	strtrim_unused(ori);

	fs = fs_get(ori);
	if (fs == NULL)
		return -ENOENT;

	p->fs = fs;
	p->path = ori;

	ret = fs->getpath(p);
	if (ret != 0)
		p->path = NULL;

	fs_put(fs);
	return ret;
}

void free_path(struct file_path *p)
{
	p->fs->putpath(p);
}

long do_syscall_open(const char *name, int flags, mode_t mode)
{
	long ret = -1;
	struct file_path p;

	ret = alloc_path(name, &p);
	if (ret != 0)
		return ret;

	ret = sys_open(p.path, flags, mode);

	free_path(&p);
	return ret;
}

long do_syscall_close(int fd)
{
	return sys_close(fd);
}

long do_syscall_read(int fd, void *buf, size_t n)
{
	if (!access_ok(buf, n))
		return -EFAULT;

	return sys_read(fd, buf, n);
}

long do_syscall_write(int fd, const void *buf, size_t n)
{
	if (!access_ok(buf, n))
		return -EFAULT;

	return sys_write(fd, buf, n);
}

long do_syscall_ioctl(int fd, int request, unsigned long arg)
{
	return sys_ioctl(fd, request, arg);
}

long do_syscall_mmap(void *addr, size_t length, int prot,
							int flags, int fd, off_t offset)
{
	return (long)vm_mmap(addr, length, prot, flags, fd, offset);
}

long do_syscall_munmap(void *addr, size_t n)
{
	return vm_munmap(addr, n);
}

long do_syscall_lseek(int fd, off_t offset, int flags)
{
	return sys_lseek(fd, offset, flags);
}

long do_syscall_fstat(int fd, struct stat *st)
{
	int ret = -EFAULT;
	struct stat tmp;

	ret = sys_fstat(fd, &tmp);
	if (ret == 0) {
		ret = copy_to_user(st, &tmp, sizeof(tmp));
		if (ret)
			ret = -EFAULT;
	}

	return ret;
}

long do_syscall_ftruncate(int fd, off_t length)
{
	return sys_ftruncate(fd, length);
}

long do_syscall_remove(const char *name)
{
	long ret = -1;
	struct file_path p;

	ret = alloc_path(name, &p);
	if (ret != 0)
		return ret;

	ret = sys_unlink(p.path);

	free_path(&p);
	return ret;
}

long do_syscall_rename(const char *oldpath, const char *newpath)
{
	long ret = -1;
	struct file_path oldp;
	struct file_path newp;

	ret = alloc_path(oldpath, &oldp);
	if (ret != 0)
		return ret;
	ret = alloc_path(newpath, &newp);
	if (ret != 0)
		goto out;

	ret = sys_rename(oldp.path, newp.path);

out:
	free_path(&oldp);
	free_path(&newp);
	return ret;
}

long do_syscall_mkdir(const char *name, mode_t mode)
{
	long ret = -1;
	struct file_path p;

	ret = alloc_path(name, &p);
	if (ret != 0)
		return ret;

	ret = sys_mkdir(p.path, mode);

	free_path(&p);
	return ret;
}

long do_syscall_rmdir(const char *name)
{
	long ret = -1;
	struct file_path p;

	ret = alloc_path(name, &p);
	if (ret != 0)
		return ret;

	ret = sys_rmdir(p.path);

	free_path(&p);
	return ret;
}

long do_syscall_readdir(int fd, void *buf, size_t cnt)
{
	if (!access_ok(buf, cnt))
		return -EFAULT;

	return sys_getdents(fd, buf, cnt);
}
