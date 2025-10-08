/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * File framework
 */

#ifndef _FILE_H
#define _FILE_H

#include <atomic.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <rbtree.h>

#include <sys/stat.h>
#include <sys/mmap.h>

/*
 * resolved the fs <-> file type
 */
struct file_system;
/*
 * resolved the poll <-> file type
 */
struct poll_table;

/*
 * File context link to lower-level drivers
 */
struct file {
	int flags;
	struct atomic_num refc;
	/* @ which file system */
	struct file_system *fs;
	/* path inside the 'fs' */
	char *path;
	/* device context (for real devive only)*/
	void *dev;
	/* file private data */
	void *priv;
	const struct file_operations *fops;
	/* current position, FS or device driver may not use it */
	off_t pos;
};

/*
 * File context link to upper-level FS
 */
struct file_desc {
	/* file descriptor */
	int fd;
	/* reference counter */
	int refc;
	/* @ which process  */
	struct process *proc;
	/* node in the process file-tree  */
	struct rb_node node;
	/* corresponding file ctx  */
	struct file *file;
	/* atclose callbacks */
	struct list_head atcloses;
};

struct file_path {
	/* @ which file system */
	struct file_system *fs;
	/* final spath inside the 'fs' */
	const char *path;
};

/*
 * File operations
 */
struct file_operations {
	int (*open)(struct file *filp, mode_t mode, void *arg);
	int (*close)(struct file *filp);
	ssize_t (*read)(struct file *filp, void *buf, size_t cnt);
	ssize_t (*write)(struct file *filp, const void *buf, size_t cnt);
	int (*mmap)(struct file *filp, struct vm_struct *vm);
	int (*ioctl)(struct file *filp, int cmd, unsigned long arg);
	int (*poll)(struct file *filp, struct poll_table *pt);

	off_t (*lseek)(struct file *filp, off_t offset, int whence);
	int (*ftruncate)(struct file *filp, off_t length);
	int (*fstat)(struct file *filp, struct stat *st);
	int (*rename)(struct file_system *fs, const char *oldpath, const char *newpath);
	int (*unlink)(struct file_system *fs, const char *path);

	ssize_t (*readdir)(struct file *filp, struct dirent *d, size_t cnt);
	int (*mkdir)(struct file_system *fs, const char *path, mode_t mode);
	int (*rmdir)(struct file_system *fs, const char *path);
};

#define NUMFD_PER_POOL (512)

struct fd_pool {
	/* node @ the process's fdtab->pools or depletedpools */
	struct rb_node node;
	/* pool's id @ the process's fdtab->pools */
	unsigned int id;
	/*
	 * to record the last allocated/freed ID,
	 * increased 1 for next allocation
	 **/
	unsigned short next;
	/* number of free fds */
	unsigned short nbits;
	/* fd free/busy bitmap */
	unsigned long bmap[NUMFD_PER_POOL/BITS_PER_LONG];
};

/*
 * Process's File Descriptor Table
 */
struct fdtab {
	/* rbroot node of the current opened fds */
	struct rb_node *fds;

	/* rbroot node of the fd bitmap allocator pools */
	struct rb_node *pools;

	/* rbroot node of the fd bitmap depleted pools */
	struct rb_node *depletedpools;

	/* number of fd bitmap pools */
	int nrpools;

	/* Process's fd table lock */
	struct spinlock lock;
	/* Process's atclose lock */
	struct spinlock atclock;
};

/*
 * Register a function to be performed at fdesc close
 */
struct fdesc_atclose {
	struct list_head node;
	void (*atclose)(struct fdesc_atclose *fdatc);
};
void fdesc_register_atclose(struct file_desc *, struct fdesc_atclose *);
bool fdesc_unregister_atclose(struct process *, struct fdesc_atclose *);

/*
 * 1. Find the desc pointer by FD
 * 2. Increase the fdesc and file refc
 */
struct file_desc *fdesc_get(int fd);

int fdesc_put(struct file_desc *fdesc);

int fdesc_dup(struct file *src, struct file_desc **dst);

static inline void file_get(struct file *f)
{
	atomic_inc(&f->refc);
}

void file_put(struct file *f);

ssize_t sys_read(int fd, void *buf, size_t n);

ssize_t sys_write(int fd, const void *buf, size_t n);

int sys_ioctl(int fd, int cmd, unsigned long arg);

off_t sys_lseek(int fd, off_t offset, int whence);

int sys_fstat(int fd, struct stat *st);

int sys_ftruncate(int fd, off_t size);

int sys_close(int fd);

int sys_open(const char *path, int flags, ...);

int sys_rename(const char *oldp, const char *newp);

int sys_unlink(const char *path);

int sys_mkdir(const char *path, mode_t mode);

int sys_rmdir(const char *path);

ssize_t sys_readdir(int fd, struct dirent *d);

ssize_t sys_getdents(int fd, struct dirent *d, size_t cnt);

int sys_dup(int oldfd);

int sys_dup2(int oldfd, int newfd);

#endif
