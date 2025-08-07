// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * REEFS RPC layer
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syslimits.h>

#include <fs.h>
#include <defs.h>
#include <rpc.h>
#include <trace.h>
#include "reefs_rpc.h"

static int reefs_flags_to_rpc(int flags)
{
	int rpc_flags = 0;

	if ((flags & O_ACCMODE) == O_RDONLY)
		rpc_flags |= REEFS_O_RDONLY;
	else if ((flags & O_ACCMODE) == O_WRONLY)
		rpc_flags |= REEFS_O_WRONLY;
	else if ((flags & O_ACCMODE) == O_RDWR)
		rpc_flags |= REEFS_O_RDWR;

	if (flags & O_CREAT)
		rpc_flags |= REEFS_O_CREAT;
	if (flags & O_EXCL)
		rpc_flags |= REEFS_O_EXCL;
	if (flags & O_TRUNC)
		rpc_flags |= REEFS_O_TRUNC;
	if (flags & O_APPEND)
		rpc_flags |= REEFS_O_APPEND;

	return rpc_flags;
}

static int reefs_whence_to_rpc(int whence)
{
	if (whence == SEEK_SET)
		return REEFS_SEEK_SET;
	if (whence == SEEK_CUR)
		return REEFS_SEEK_CUR;
	if (whence == SEEK_END)
		return REEFS_SEEK_END;
	return -1;
}

static int reefs_rpc_call(struct reefs_cmd *cmd, size_t size)
{
	int ret = -1;

	ret = rpc_call_sync(MBEDTEE_RPC_REEFS, cmd, size);
	if (ret != 0)
		return ret;

	return mbedtee_rpc_gp_to_errno(cmd->hdr.ret);
}

int reefs_rpc_open(const char *path, int wrflag)
{
	off_t ret = -1;
	size_t pathl = strnlen(path, FS_PATH_MAX - 1) + 1;
	size_t length = pathl + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_OPEN;
	cmd->flags = reefs_flags_to_rpc(wrflag);
	strlcpy(cmd->data, path, pathl);

	ret = reefs_rpc_call(cmd, length);
	rpc_shm_free(cmd);
	return ret;
}

int reefs_rpc_close(int fd)
{
	struct reefs_cmd cmd = {0};

	cmd.hdr.op = REEFS_CLOSE;
	cmd.fd = fd;

	return reefs_rpc_call(&cmd, sizeof(cmd));
}

ssize_t reefs_rpc_read(int fd, void *buff, size_t len)
{
	ssize_t ret = -1;
	size_t length = len + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	if (length < len)
		return -EINVAL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_READ;
	cmd->fd = fd;
	cmd->len = len;

	ret = reefs_rpc_call(cmd, length);

	if (ret < 0)
		goto out;

	if (ret > len) {
		ret = -E2BIG;
		goto out;
	}

	memcpy(buff, cmd->data, ret);

out:
	rpc_shm_free(cmd);
	return ret;
}

ssize_t reefs_rpc_write(int fd, void *buff, size_t len)
{
	ssize_t ret = -1;
	size_t length = len + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	if (length < len)
		return -EINVAL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_WRITE;
	cmd->fd = fd;
	cmd->len = len;

	memcpy(cmd->data, buff, len);

	ret = reefs_rpc_call(cmd, length);
	if (ret < 0)
		goto out;

	if (ret > len)
		ret = -E2BIG;

	if (ret == 0)
		ret = -ENOSPC;

out:
	rpc_shm_free(cmd);
	return ret;
}

int reefs_rpc_ftruncate(int fd, off_t len)
{
	struct reefs_cmd cmd = {0};

	cmd.hdr.op = REEFS_TRUNC;
	cmd.fd = fd;
	cmd.len = len;

	return reefs_rpc_call(&cmd, sizeof(cmd));
}

int reefs_rpc_unlink(const char *path)
{
	off_t ret = -1;
	size_t pathl = strnlen(path, FS_PATH_MAX - 1) + 1;
	size_t length = pathl + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_UNLINK;
	strlcpy(cmd->data, path, pathl);

	ret = reefs_rpc_call(cmd, length);
	rpc_shm_free(cmd);
	return ret;
}

int reefs_rpc_rename(const char *oldpath, const char *newpath)
{
	off_t ret = -1;
	size_t pathl = strnlen(oldpath, FS_PATH_MAX - 1) + 1;
	size_t pathln = strnlen(newpath, FS_PATH_MAX - 1) + 1;
	size_t length = pathl + pathln + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_RENAME;
	strlcpy(cmd->data, oldpath, pathl);
	strlcpy(cmd->data + pathl, newpath, pathln);

	ret = reefs_rpc_call(cmd, length);
	rpc_shm_free(cmd);
	return ret;
}

int reefs_rpc_mkdir(const char *path, mode_t mode)
{
	off_t ret = -1;
	size_t pathl = strnlen(path, FS_PATH_MAX - 1) + 1;
	size_t length = pathl + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_MKDIR;
	cmd->flags = mode;
	strlcpy(cmd->data, path, pathl);

	ret = reefs_rpc_call(cmd, length);
	rpc_shm_free(cmd);
	return ret;
}

int reefs_rpc_opendir(const char *path)
{
	off_t ret = -1;
	size_t pathl = strnlen(path, FS_PATH_MAX - 1) + 1;
	size_t length = pathl + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_OPENDIR;
	strlcpy(cmd->data, path, pathl);

	ret = reefs_rpc_call(cmd, length);
	rpc_shm_free(cmd);
	return ret;
}

int reefs_rpc_closedir(int dir)
{
	struct reefs_cmd cmd = {0};

	cmd.hdr.op = REEFS_CLOSEDIR;
	cmd.fd = dir;

	return reefs_rpc_call(&cmd, sizeof(cmd));
}

ssize_t reefs_rpc_readdir(int dir, struct reefs_dirent *d, size_t cnt)
{
	ssize_t ret = -1;
	size_t length = cnt + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_READDIR;
	cmd->fd = dir;
	cmd->len = cnt;

	ret = reefs_rpc_call(cmd, length);

	if (ret < 0)
		goto out;

	if (ret > cnt) {
		ret = -E2BIG;
		goto out;
	}

	memcpy(d, cmd->data, ret);

out:
	rpc_shm_free(cmd);
	return ret;
}

int reefs_rpc_seekdir(int dir, off_t off)
{
	struct reefs_cmd cmd = {0};

	cmd.hdr.op = REEFS_SEEKDIR;
	cmd.fd = dir;
	cmd.len = off;

	return reefs_rpc_call(&cmd, sizeof(cmd));
}

int reefs_rpc_rmdir(const char *path)
{
	off_t ret = -1;
	size_t pathl = strnlen(path, FS_PATH_MAX - 1) + 1;
	size_t length = pathl + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_RMDIR;
	strlcpy(cmd->data, path, pathl);

	ret = reefs_rpc_call(cmd, length);
	rpc_shm_free(cmd);
	return ret;
}

off_t reefs_rpc_lseek(int fd, off_t off, int flags)
{
	struct reefs_cmd cmd = {0};
	int rpc_whence = reefs_whence_to_rpc(flags);

	if (rpc_whence < 0)
		return -EINVAL;

	cmd.hdr.op = REEFS_SEEK;
	cmd.fd = fd;
	cmd.flags = rpc_whence;
	cmd.len = off;

	return reefs_rpc_call(&cmd, sizeof(cmd));
}

ssize_t reefs_rpc_pread(int fd, void *buff, size_t len, off_t off)
{
	ssize_t ret = -1;
	size_t length = len + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	if (length < len)
		return -EINVAL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_PREAD;
	cmd->fd = fd;
	cmd->len = len;
	cmd->flags = off;

	ret = reefs_rpc_call(cmd, length);

	if (ret < 0)
		goto out;

	if (ret > len) {
		ret = -E2BIG;
		goto out;
	}

	memcpy(buff, cmd->data, ret);

out:
	rpc_shm_free(cmd);
	return ret;
}

ssize_t reefs_rpc_pwrite(int fd, void *buff, size_t len, off_t off)
{
	ssize_t ret = -1;
	size_t length = len + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	if (length < len)
		return -EINVAL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_PWRITE;
	cmd->fd = fd;
	cmd->len = len;
	cmd->flags = off;

	memcpy(cmd->data, buff, len);

	ret = reefs_rpc_call(cmd, length);
	if (ret < 0)
		goto out;

	if (ret > len)
		ret = -E2BIG;

	if (ret == 0)
		ret = -ENOSPC;

out:
	rpc_shm_free(cmd);
	return ret;
}

int reefs_rpc_fstat(int fd, struct reefs_stat *st, int flags)
{
	int ret = -1;
	size_t length = sizeof(struct reefs_stat) + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (!cmd)
		return -ENOMEM;

	cmd->hdr.op = REEFS_FSTAT;
	cmd->fd = fd;
	cmd->flags = flags;

	ret = reefs_rpc_call(cmd, length);
	if (ret == 0)
		memcpy(st, cmd->data, sizeof(struct reefs_stat));
	rpc_shm_free(cmd);
	return ret;
}
