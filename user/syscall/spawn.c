// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * POSIX spawn implementation.
 *
 * Provides posix_spawn/posix_spawnp and posix_spawn_file_actions_*.
 * The kernel applies the file-actions in the child very early via
 * libc entry (see user/pthread/entry.c).
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <spawn.h>
#include <syscall.h>

static int fa_append(posix_spawn_file_actions_t *fa, const void *rec, size_t len)
{
	if (!fa || !rec)
		return EINVAL;
	if (len < sizeof(struct mtee_spawn_rec_hdr))
		return EINVAL;
	if (fa->used + len > sizeof(fa->buf))
		return E2BIG;
	memcpy(fa->buf + fa->used, rec, len);
	fa->used += len;
	return 0;
}

int posix_spawn_file_actions_init(posix_spawn_file_actions_t *fa)
{
	if (!fa)
		return EINVAL;
	fa->used = 0;
	memset(fa->buf, 0, sizeof(fa->buf));
	return 0;
}

int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *fa)
{
	if (!fa)
		return EINVAL;
	fa->used = 0;
	memset(fa->buf, 0, sizeof(fa->buf));
	return 0;
}

int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *fa, int fd)
{
	struct mtee_spawn_rec_close rec;

	if (!fa)
		return EINVAL;

	rec.h.type = MTEE_SPAWN_ACT_CLOSE;
	rec.h.reserved = 0;
	rec.h.len = sizeof(rec);
	rec.fd = fd;
	return fa_append(fa, &rec, sizeof(rec));
}

int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *fa, int fd, int newfd)
{
	struct mtee_spawn_rec_dup2 rec;

	if (!fa)
		return EINVAL;

	rec.h.type = MTEE_SPAWN_ACT_DUP2;
	rec.h.reserved = 0;
	rec.h.len = sizeof(rec);
	rec.fd = fd;
	rec.newfd = newfd;
	return fa_append(fa, &rec, sizeof(rec));
}

int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *fa,
	int fd, const char *path, int oflag, mode_t mode)
{
	size_t plen;
	struct mtee_spawn_rec_open_fixed fixed;
	unsigned char tmp[sizeof(fixed) + 256];

	if (!fa || !path)
		return EINVAL;

	plen = strnlen(path, 255);
	if (plen == 255 && path[255] != '\0')
		return ENAMETOOLONG;

	fixed.h.type = MTEE_SPAWN_ACT_OPEN;
	fixed.h.reserved = 0;
	fixed.fd = fd;
	fixed.oflag = oflag;
	fixed.mode = mode;
	fixed.path_len = plen + 1;
	fixed.h.len = sizeof(fixed) + fixed.path_len;

	if (fixed.h.len > sizeof(tmp))
		return E2BIG;

	memcpy(tmp, &fixed, sizeof(fixed));
	memcpy(tmp + sizeof(fixed), path, fixed.path_len);
	return fa_append(fa, tmp, fixed.h.len);
}

static int do_spawn(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *fa,
	const posix_spawnattr_t *attrp,
	char *const argv[],
	char *const envp[])
{
	long ret = 0;
	long args[6];

	if (!pid || !path || !argv)
		return EINVAL;
	if (attrp)
		return ENOTSUP;
	if (envp)
		return ENOTSUP;

	/* Optional: validate file-actions buffer shape lightly. */
	if (fa && fa->used > sizeof(fa->buf))
		return EINVAL;

	args[0] = (long)pid;
	args[1] = (long)path;
	args[2] = (long)fa;
	args[3] = (long)attrp;
	args[4] = (long)argv;
	args[5] = (long)envp;

	ret = syscall1(SYSCALL_POSIX_SPAWN, args);
	if (ret >= 0)
		return 0;

	return syscall_errno(ret);
}

int posix_spawn(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *file_actions,
	const posix_spawnattr_t *attrp,
	char *const argv[],
	char *const envp[])
{
	return do_spawn(pid, path, file_actions, attrp, argv, envp);
}

int posix_spawnp(pid_t *pid, const char *file,
	const posix_spawn_file_actions_t *file_actions,
	const posix_spawnattr_t *attrp,
	char *const argv[],
	char *const envp[])
{
	/* No PATH resolution yet; behave like posix_spawn(). */
	return do_spawn(pid, file, file_actions, attrp, argv, envp);
}
