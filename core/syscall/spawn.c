// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * POSIX-like process spawn syscall + in-kernel helper.
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <file.h>
#include <wait.h>
#include <spawn.h>
#include <thread.h>
#include <process.h>
#include <uaccess.h>
#include <ksignal.h>
#include <syscall.h>

#define INHERIT_FD_MAX 64

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

static int spawn_open_to(struct process *proc, const char *path,
	int flags, mode_t mode, int fd)
{
	int ret = 0;
	struct file_path p;

	ret = alloc_kpath(path, &p);
	if (ret != 0)
		return ret;

	ret = fdesc_open_to(proc, p.path, flags, mode, fd);

	free_path(&p);

	return ret;
}

static int spawn_inherit_one_fd(struct process *child, int srcfd)
{
	int ret = 0;
	struct file_desc *src = NULL;

	if (srcfd < 0 || (size_t)srcfd >= PROCESS_FD_MAX)
		return -EBADF;

	src = fdesc_get(srcfd);
	if (!src)
		return -EBADF;

	if (src->flags & FD_CLOEXEC) {
		fdesc_put(src);
		return 0;
	}

	ret = fdesc_dup_to(child, src->file, srcfd);
	if (ret >= 0)
		ret = 0;
	fdesc_put(src);
	return ret;
}

static int spawn_apply_file_actions(struct process *child,
	const posix_spawn_file_actions_t *fa)
{
	size_t off = 0;

	if (!fa || fa->used == 0)
		return 0;
	if (fa->used > sizeof(fa->buf))
		return -EINVAL;

	while (off + sizeof(struct mtee_spawn_rec_hdr) <= fa->used) {
		const struct mtee_spawn_rec_hdr *h =
			(const struct mtee_spawn_rec_hdr *)(fa->buf + off);
		uint32_t len = h->len;
		int ret = 0;

		if (len < sizeof(*h) || off + len > fa->used)
			return -EINVAL;

		switch (h->type) {
		case MTEE_SPAWN_ACT_CLOSE: {
			const struct mtee_spawn_rec_close *r =
				(const struct mtee_spawn_rec_close *)(fa->buf + off);
			if (len != sizeof(*r)) {
				ret = -EINVAL;
				break;
			}
			ret = fdesc_close_to(child, r->fd);
			break;
		}
		case MTEE_SPAWN_ACT_DUP2: {
			const struct mtee_spawn_rec_dup2 *r =
				(const struct mtee_spawn_rec_dup2 *)(fa->buf + off);
			if (len != sizeof(*r)) {
				ret = -EINVAL;
				break;
			}
			ret = fdesc_dup2_to(child, r->fd, r->newfd);
			if (ret >= 0)
				ret = 0;
			break;
		}
		case MTEE_SPAWN_ACT_OPEN: {
			const struct mtee_spawn_rec_open_fixed *fx =
				(const struct mtee_spawn_rec_open_fixed *)(fa->buf + off);
			const char *path = NULL;
			if (len < sizeof(*fx)) {
				ret = -EINVAL;
				break;
			}
			if (fx->path_len == 0 || sizeof(*fx) + fx->path_len != len) {
				ret = -EINVAL;
				break;
			}
			path = (const char *)(fa->buf + off + sizeof(*fx));
			if (path[fx->path_len - 1] != '\0') {
				ret = -EINVAL;
				break;
			}

			ret = spawn_open_to(child, path, fx->oflag, fx->mode, fx->fd);
			break;
		}
		default:
			ret = -EINVAL;
			break;
		}

		if (ret != 0)
			return ret;

		off += len;
	}

	return 0;
}

static bool spawn_fdset_has(const int *arr, size_t n, int fd)
{
	int i = 0;

	for (i = 0; i < n; i++) {
		if (arr[i] == fd)
			return true;
	}
	return false;
}

static void spawn_fdset_add(int *arr, size_t *n, size_t max, int fd)
{
	if (*n >= max)
		return;
	if (spawn_fdset_has(arr, *n, fd))
		return;
	arr[(*n)++] = fd;
}

static void spawn_fdset_del(int *arr, size_t *n, int fd)
{
	int i = 0;

	for (i = 0; i < *n; i++) {
		if (arr[i] == fd) {
			arr[i] = arr[*n - 1];
			(*n)--;
			return;
		}
	}
}

static int spawn_build_inherit_set(const posix_spawn_file_actions_t *fa,
	int *inherit_fds, size_t inherit_max, size_t *inherit_nr)
{
	size_t off = 0;
	int created[INHERIT_FD_MAX];
	size_t created_nr = 0;

	*inherit_nr = 0;

	/*
	 * POSIX-like behavior: inherit standard fds by default so that
	 * `cmd | other` style pipelines propagate through nested spawns.
	 */
	spawn_fdset_add(inherit_fds, inherit_nr, inherit_max, 0);
	spawn_fdset_add(inherit_fds, inherit_nr, inherit_max, 1);
	spawn_fdset_add(inherit_fds, inherit_nr, inherit_max, 2);
	if (!fa || fa->used == 0)
		return 0;
	if (fa->used > sizeof(fa->buf))
		return -EINVAL;

	while (off + sizeof(struct mtee_spawn_rec_hdr) <= fa->used) {
		const struct mtee_spawn_rec_hdr *h =
			(const struct mtee_spawn_rec_hdr *)(fa->buf + off);
		uint32_t len = h->len;

		if (len < sizeof(*h) || off + len > fa->used)
			return -EINVAL;

		if (h->type == MTEE_SPAWN_ACT_OPEN) {
			const struct mtee_spawn_rec_open_fixed *fx =
				(const struct mtee_spawn_rec_open_fixed *)(fa->buf + off);
			if (len < sizeof(*fx))
				return -EINVAL;
			/*
			 * The actual open happens later (apply_file_actions), but if an fd is
			 * created via OPEN before it is used as a DUP2 source, it should not be
			 * inherited from the parent.
			 */
			spawn_fdset_add(created, &created_nr, ARRAY_SIZE(created), fx->fd);
		} else if (h->type == MTEE_SPAWN_ACT_DUP2) {
			const struct mtee_spawn_rec_dup2 *r =
				(const struct mtee_spawn_rec_dup2 *)(fa->buf + off);
			if (len != sizeof(*r))
				return -EINVAL;

			/*
			 * Inherit only if the source fd is not created by earlier file-actions.
			 * (e.g. open(fd=3) then dup2(3->1) should not require parent fd 3).
			 */
			if (!spawn_fdset_has(created, created_nr, r->fd) && *inherit_nr < inherit_max)
				spawn_fdset_add(inherit_fds, inherit_nr, inherit_max, r->fd);

			/* dup2() makes newfd available for later actions */
			spawn_fdset_add(created, &created_nr, ARRAY_SIZE(created), r->newfd);
		} else if (h->type == MTEE_SPAWN_ACT_CLOSE) {
			const struct mtee_spawn_rec_close *r =
				(const struct mtee_spawn_rec_close *)(fa->buf + off);
			if (len != sizeof(*r))
				return -EINVAL;

			/*
			 * close(fd) will fail with EBADF if fd was never available in the child.
			 * If the fd is not created by earlier actions (open/dup2), it must be
			 * inherited from the parent so that close() can succeed.
			 */
			if (!spawn_fdset_has(created, created_nr, r->fd) && *inherit_nr < inherit_max)
				spawn_fdset_add(inherit_fds, inherit_nr, inherit_max, r->fd);
			spawn_fdset_del(created, &created_nr, r->fd);
		}

		off += len;
	}

	return 0;
}

int kposix_spawn(pid_t *pid, const char *name,
	const posix_spawn_file_actions_t *fa,
	char *const argv[])
{
	pid_t cpid = -1;
	struct process *child = NULL;
	int ret = 0, inherit_fds[INHERIT_FD_MAX];
	size_t inherit_nr = 0, i = 0;

	if (!pid || !name || !argv)
		return -EINVAL;

	memset(inherit_fds, 0, sizeof(inherit_fds));

	ret = spawn_build_inherit_set(fa, inherit_fds,
			ARRAY_SIZE(inherit_fds), &inherit_nr);
	if (ret != 0)
		return ret;

	cpid = process_create(name, argv);
	if (cpid < 0)
		return cpid;

	child = process_get(cpid);
	if (!child)
		return -ESRCH;

	atomic_orr(&child->wait_state, PROC_WAIT_WAITABLE);

	for (i = 0; i < inherit_nr; i++) {
		ret = spawn_inherit_one_fd(child, inherit_fds[i]);
		if (ret != 0)
			goto fail_destroy;
	}

	ret = spawn_apply_file_actions(child, fa);
	if (ret != 0)
		goto fail_destroy;

	*pid = cpid;
	sched_ready(cpid);

	/* Keep this reference to make the child waitable (reaped by waitpid). */
	return 0;

fail_destroy:
	process_put(child);
	process_destroy(child);
	return ret;
}

long syscall_posix_spawn(struct thread_ctx *regs)
{
	long args[6] = {0};
	pid_t pid = -1, *upid = NULL;
	const char *uname = NULL;
	char * const *uargv = NULL;
	void *uattrp = NULL, *uenvp = NULL;
	const posix_spawn_file_actions_t *ufa = NULL;
	posix_spawn_file_actions_t kfa;
	struct process *child = NULL;
	int ret = 0, inherit_fds[INHERIT_FD_MAX];
	size_t inherit_nr = 0, i = 0;
	char name[PROCESS_NAME_LEN];

	BUILD_ERROR_ON(sizeof(kfa) < 256);

	memset(&kfa, 0, sizeof(kfa));
	memset(inherit_fds, 0, sizeof(inherit_fds));

	if (copy_from_user(&args, (void *)regs->r[ARG_REG + 1], sizeof(args)))
		return -EFAULT;

	upid = (pid_t *)args[0];
	uname = (const char *)args[1];
	ufa = (const posix_spawn_file_actions_t *)args[2];
	uattrp = (void *)args[3];
	uargv = (char * const *)args[4];
	uenvp = (void *)args[5];

	if (!upid || !uname || !uargv)
		return -EFAULT;
	if (uattrp || uenvp)
		return -ENOTSUP;
	if (!access_ok(upid, sizeof(*upid)))
		return -EFAULT;
	if (!access_ok(uargv, MAX_ARGV_NUM * sizeof(char *)))
		return -EFAULT;

	ret = strncpy_from_user(name, uname, sizeof(name));
	if (ret < 0)
		return ret;

	/*
	 * Always build an inherit set. Even when file_actions is NULL, we want
	 * POSIX-like behavior: inherit stdio (0/1/2) by default.
	 */
	ret = spawn_build_inherit_set(NULL, inherit_fds,
			ARRAY_SIZE(inherit_fds), &inherit_nr);
	if (ret != 0)
		return ret;

	if (ufa) {
		if (!access_ok(ufa, sizeof(*ufa)))
			return -EFAULT;
		if (copy_from_user(&kfa, (void *)ufa, sizeof(kfa)))
			return -EFAULT;

		ret = spawn_build_inherit_set(&kfa, inherit_fds,
				ARRAY_SIZE(inherit_fds), &inherit_nr);
		if (ret != 0)
			return ret;
	}

	pid = process_create(name, uargv);
	if (pid < 0)
		return pid;

	child = process_get(pid);
	if (!child)
		return -ESRCH;

	atomic_orr(&child->wait_state, PROC_WAIT_WAITABLE);

	for (i = 0; i < inherit_nr; i++) {
		ret = spawn_inherit_one_fd(child, inherit_fds[i]);
		if (ret != 0)
			goto fail_destroy;
	}

	ret = spawn_apply_file_actions(child, ufa ? &kfa : NULL);
	if (ret != 0)
		goto fail_destroy;

	if (copy_to_user(upid, &pid, sizeof(pid))) {
		ret = -EFAULT;
		goto fail_destroy;
	}

	sched_ready(pid);

	/* Keep this reference to make the child waitable (reaped by waitpid). */
	return 0;

fail_destroy:
	process_put(child);
	process_destroy(child);
	return ret;
}
