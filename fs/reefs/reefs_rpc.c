// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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

#define DEFINE_BUFF(x)														\
	size_t pathl = strnlen(path, FS_NAME_MAX - 1) + 1;						\
	size_t length = pathl + sizeof(struct reefs_cmd);						\
	long x[(FS_NAME_MAX + sizeof(struct reefs_cmd))/BYTES_PER_LONG + 1]		\

int reefs_rpc_open(const char *path, int wrflag)
{
	off_t ret = -1;
	DEFINE_BUFF(buff);
	struct reefs_cmd *cmd = (void *)buff;

	cmd->op = REEFS_OPEN;
	cmd->flags = O_RDWR;
	strlcpy(cmd->data, path, pathl);

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		return ret;

	return cmd->ret;
}

int reefs_rpc_create(const char *path, mode_t mode)
{
	off_t ret = -1;
	DEFINE_BUFF(buff);
	struct reefs_cmd *cmd = (void *)buff;

	cmd->op = REEFS_OPEN;
	cmd->flags = O_RDWR | 0x40;
	strlcpy(cmd->data, path, pathl);

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		return ret;

	return cmd->ret;
}

int reefs_rpc_close(int fd)
{
	off_t ret = -1;
	struct reefs_cmd cmd = {0};

	cmd.op = REEFS_CLOSE;
	cmd.fd = fd;

	ret = rpc_call_sync(RPC_REEFS, &cmd, sizeof(cmd));
	if (ret != 0)
		return ret;

	return cmd.ret;
}

ssize_t reefs_rpc_read(int fd, void *buff, size_t len)
{
	ssize_t ret = -1;
	size_t length = len + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (cmd == NULL)
		return -ENOMEM;

	cmd->op = REEFS_READ;
	cmd->fd = fd;
	cmd->len = len;

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		goto out;

	ret = cmd->ret;

	if ((ret < 0) && (ret >= -__ELASTERROR))
		goto out;

	if ((ret < 0) || (ret > len)) {
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

	cmd = rpc_shm_alloc(length);
	if (cmd == NULL)
		return -ENOMEM;

	cmd->op = REEFS_WRITE;
	cmd->fd = fd;
	cmd->len = len;

	memcpy(cmd->data, buff, len);

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		goto out;

	ret = cmd->ret;
	if (ret < 0 || ret > len)
		ret = -E2BIG;

	if (ret == 0)
		ret = -ENOSPC;

out:
	rpc_shm_free(cmd);
	return ret;
}

int reefs_rpc_ftruncate(int fd, off_t len)
{
	off_t ret = -1;
	struct reefs_cmd cmd = {0};

	cmd.op = REEFS_TRUNC;
	cmd.fd = fd;
	cmd.len = len;

	ret = rpc_call_sync(RPC_REEFS, &cmd, sizeof(cmd));
	if (ret != 0)
		return ret;

	return cmd.ret;
}

int reefs_rpc_unlink(const char *path)
{
	off_t ret = -1;
	DEFINE_BUFF(buff);
	struct reefs_cmd *cmd = (void *)buff;

	cmd->op = REEFS_UNLINK;
	strlcpy(cmd->data, path, pathl);

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		return ret;

	return cmd->ret;
}

int reefs_rpc_rename(const char *oldpath, const char *newpath)
{
	off_t ret = -1;
	size_t pathl = strnlen(oldpath, FS_NAME_MAX - 1) + 1;
	size_t pathln = strnlen(newpath, FS_NAME_MAX - 1) + 1;
	size_t length = pathl + pathln + sizeof(struct reefs_cmd);
	char buff[FS_NAME_MAX * 2 + sizeof(struct reefs_cmd)];
	struct reefs_cmd *cmd = (void *)buff;

	memset(cmd, 0, sizeof(struct reefs_cmd));

	cmd->op = REEFS_RENAME;
	strlcpy(cmd->data, oldpath, pathl);
	strlcpy(cmd->data + pathl, newpath, pathln);

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		return ret;

	return cmd->ret;
}

int reefs_rpc_mkdir(const char *path, mode_t mode)
{
	off_t ret = -1;
	DEFINE_BUFF(buff);
	struct reefs_cmd *cmd = (void *)buff;

	cmd->op = REEFS_MKDIR;
	cmd->flags = mode;
	strlcpy(cmd->data, path, pathl);

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		return ret;

	return cmd->ret;
}

int reefs_rpc_opendir(const char *path)
{
	off_t ret = -1;
	DEFINE_BUFF(buff);
	struct reefs_cmd *cmd = (void *)buff;

	cmd->op = REEFS_OPENDIR;
	strlcpy(cmd->data, path, pathl);

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		return ret;

	return cmd->ret;
}

int reefs_rpc_closedir(int dir)
{
	off_t ret = -1;
	struct reefs_cmd cmd = {0};

	cmd.op = REEFS_CLOSEDIR;
	cmd.fd = dir;

	ret = rpc_call_sync(RPC_REEFS, &cmd, sizeof(cmd));
	if (ret != 0)
		return ret;

	return cmd.ret;
}

ssize_t reefs_rpc_readdir(int dir, struct reefs_dirent *d, size_t cnt)
{
	ssize_t ret = -1;
	size_t length = cnt + sizeof(struct reefs_cmd);
	struct reefs_cmd *cmd = NULL;

	cmd = rpc_shm_alloc(length);
	if (cmd == NULL)
		return -ENOMEM;

	cmd->op = REEFS_READDIR;
	cmd->fd = dir;
	cmd->len = cnt;

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		goto out;

	ret = cmd->ret;

	if (ret == EOF)
		goto out;

	if (ret < 0 || ret > cnt) {
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
	int ret = -1;
	struct reefs_cmd cmd = {0};

	cmd.op = REEFS_SEEKDIR;
	cmd.fd = dir;
	cmd.len = off;

	ret = rpc_call_sync(RPC_REEFS, &cmd, sizeof(cmd));
	if (ret != 0)
		return ret;

	return cmd.ret;
}

int reefs_rpc_rmdir(const char *path)
{
	off_t ret = -1;
	DEFINE_BUFF(buff);
	struct reefs_cmd *cmd = (void *)buff;

	cmd->op = REEFS_RMDIR;
	strlcpy(cmd->data, path, pathl);

	ret = rpc_call_sync(RPC_REEFS, cmd, length);
	if (ret != 0)
		return ret;

	return cmd->ret;
}

off_t reefs_rpc_lseek(int fd, off_t off, int flags)
{
	off_t ret = -1;
	struct reefs_cmd cmd = {0};

	cmd.op = REEFS_SEEK;
	cmd.fd = fd;
	cmd.flags = flags;
	cmd.len = off;

	ret = rpc_call_sync(RPC_REEFS, &cmd, sizeof(cmd));
	if (ret != 0)
		return ret;

	return cmd.ret;
}
