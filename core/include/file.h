/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * File framework
 */

#ifndef _FILE_H
#define _FILE_H

#ifdef __cplusplus
extern "C" {
#endif

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

struct fdesc_atclose;

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
#if defined(CONFIG_FILE_DEBUG)
	struct list_head fnode;
	char owner[64];
#endif
};

/*
 * fdesc flags
 * FD_CLOEXEC: close-on-exec flag (POSIX standard)
 * FD_CLOSED:  internal flag for closed fdesc  (invisible to lookup)
 * FD_OPENING: internal flag for opening fdesc (invisible to lookup)
 */
#define FD_CLOSED   (1 << 30)
#define FD_OPENING	(1 << 29)

/*
 * File context link to upper-level FS
 */
struct file_desc {
	/* file descriptor */
	int fd;
	/* fdesc flags (e.g. FD_CLOEXEC, FD_CLOSED) */
	int flags;
	/* reference counter */
	int refc;
	/* @ which process  */
	struct process *proc;
	/* node in the process file-tree  */
	struct rb_node node;
	/* corresponding file ctx  */
	struct file *file;
	/* atclose callbacks */
	struct fdesc_atclose *atcloses;
};

struct file_path {
	/* @ which file system */
	struct file_system *fs;
	/* final path inside the 'fs' */
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
	/* node in the process's fdtab->pools or depletedpools */
	struct rb_node node;
	/* pool's id @ the process's fdtab->pools */
	unsigned int id;
	/*
	 * Record the last allocated/freed ID.
	 * Increase it by 1 for the next allocation.
	 */
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
	struct fdesc_atclose *next;
	struct file_desc *owner;
	void (*atclose)(struct fdesc_atclose *fdatc);
};
void fdesc_register_atclose(struct file_desc *, struct fdesc_atclose *,
	void (*atclose)(struct fdesc_atclose *fdatc));
bool fdesc_unregister_atclose(struct process *, struct fdesc_atclose *);

/*
 * 1. Find the desc pointer by FD
 * 2. Increase the fdesc and file refc
 */
struct file_desc *fdesc_get(int fd);

int fdesc_put(struct file_desc *fdesc);

int fdesc_dup(struct file *src, struct file_desc **dst);

int fdesc_dup_to(struct process *proc, struct file *src, int newfd);

int fdesc_dup2_to(struct process *proc, int oldfd, int newfd);

int fdesc_close_to(struct process *proc, int fd);

int fdesc_open_to(struct process *proc, const char *path,
	int flags, mode_t mode, int fd);

int fdesc_close_cloexec(struct process *proc);

void fdesc_close_all(struct process *proc);

int fdesc_alloc_pseudo(struct file_desc **ppd,
	const struct file_operations *fops, int fflags);

void fdesc_free(struct file_desc *d);

int file_alloc_pseudo(struct file **ppf,
	const struct file_operations *fops, int fflags);

static inline void file_get(struct file *f)
{
	atomic_inc(&f->refc);
}

void file_put(struct file *f);

bool file_can_poll(struct file *f);

ssize_t sys_read(int fd, void *buf, size_t n);

ssize_t sys_pread(int fd, void *buf, size_t n, off_t offset);

ssize_t sys_write(int fd, const void *buf, size_t n);

ssize_t sys_pwrite(int fd, const void *buf, size_t n, off_t offset);

int sys_ioctl(int fd, int cmd, unsigned long arg);

off_t sys_lseek(int fd, off_t offset, int whence);

int sys_fstat(int fd, struct stat *st);

int sys_stat(const char *path, struct stat *st);

int sys_ftruncate(int fd, off_t size);

int sys_close(int fd);

int sys_open(const char *path, int flags, ...);

int sys_rename(const char *oldp, const char *newp);

int sys_unlink(const char *path);

int sys_mkdir(const char *path, mode_t mode);

int sys_rmdir(const char *path);

ssize_t sys_readdir(int fd, struct dirent *d, size_t cnt);

int sys_dup(int oldfd);

int sys_dup2(int oldfd, int newfd);

int sys_fcntl(int fd, int cmd, unsigned long arg);

int sys_pipe(int pipefd[2]);

int sys_pipe2(int pipefd[2], int flags);

/*
 * Publish the file_desc to the process's fdtab.
 * It clears the FD_OPENING flag, making the fd visible to others.
 */
static inline void fdesc_publish(struct file_desc *d)
{
	atomic_bic((struct atomic_num *)&d->flags, FD_OPENING);
}

#ifdef __cplusplus
}
#endif
#endif
