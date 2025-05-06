/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * REEFS rpc layer
 */

#ifndef _REEFS_RPC_H
#define _REEFS_RPC_H

#include <rpc.h>
#include <rpc/reefs.h>

int reefs_rpc_open(const char *path, int wrflag);
int reefs_rpc_create(const char *path, mode_t mode);
int reefs_rpc_close(int fd);
ssize_t reefs_rpc_read(int fd, void *buff, size_t len);
ssize_t reefs_rpc_write(int fd, void *buff, size_t len);
int reefs_rpc_ftruncate(int fd, off_t len);
int reefs_rpc_unlink(const char *path);
int reefs_rpc_rename(const char *oldpath, const char *newpath);
int reefs_rpc_mkdir(const char *path, mode_t mode);
int reefs_rpc_opendir(const char *path);
int reefs_rpc_closedir(int dir);
ssize_t reefs_rpc_readdir(int dir, struct reefs_dirent *d, size_t cnt);
int reefs_rpc_seekdir(int dir, off_t off);
int reefs_rpc_rmdir(const char *path);
off_t reefs_rpc_lseek(int fd, off_t off, int whence);

#endif
