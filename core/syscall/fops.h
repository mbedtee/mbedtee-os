/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * file operations @ syscall layer
 */

#ifndef _SYSCALL_FOPS_H
#define _SYSCALL_FOPS_H

#ifdef __cplusplus
extern "C" {
#endif

long do_syscall_open(const char *path, int flags, mode_t mode);

long do_syscall_close(int fd);

long do_syscall_read(int fd, void *buf, size_t n);

long do_syscall_write(int fd, const void *buf, size_t n);

long do_syscall_pread(int fd, void *buf, size_t n, off_t offset);

long do_syscall_pwrite(int fd, const void *buf, size_t n,
	off_t offset);

long do_syscall_ioctl(int fd, int request, unsigned long arg);

long do_syscall_lseek(int fd, off_t offset, int flags);

long do_syscall_unlink(const char *path);

long do_syscall_fstat(int fd, struct stat *st);

long do_syscall_stat(const char *path, struct stat *st);

long do_syscall_rename(const char *oldpath, const char *newpath);

long do_syscall_ftruncate(int fd, off_t size);

long do_syscall_mkdir(const char *path, mode_t mode);

long do_syscall_rmdir(const char *path);

long do_syscall_readdir(int fd, void *buf, size_t cnt);

long do_syscall_mmap(void *addr, size_t length, int prot,
							int flags, int fd, off_t offset);

long do_syscall_munmap(void *addr, size_t length);

long do_syscall_poll(struct pollfd *ufds, nfds_t nfds, int msecs);

long do_syscall_select(int nfds, fd_set *r_u, fd_set *w_u,
		       fd_set *e_u, struct timespec *tsp,
		       const sigset_t *usigmask);

#ifdef __cplusplus
}
#endif
#endif
