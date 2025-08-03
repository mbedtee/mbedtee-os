/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * FS framework
 */

#ifndef _FS_H
#define _FS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <string.h>

#include <trace.h>
#include <buddy.h>
#include <mutex.h>
#include <list.h>
#include <file.h>
#include <ktime.h>
#include <defs.h>
#include <dirent.h>

#define FS_PATH_MAX			(512u)
#define FS_MNT_MAX			(32u)
#define FS_NAME_MAX			(256u)

struct fs_mnt {
	/* mount point */
	const char *path;

	/* for ramfs only */
	/* ramfs address */
	void *addr;
	/* ramfs size */
	size_t size;
};

struct file_system {
	/* FS name */
	const char *name;
	const char *type;
	/* FS mount information */
	struct fs_mnt mnt;

	/* FS private data, such as sub-fs or device ptrs */
	void *priv;

	/* FS entry in the system list */
	struct list_head node;
	/* file opetations under this FS */
	const struct file_operations *fops;

	/* FS reference counter */
	int refc;

	/* FS specific callbacks */
	int (*mount)(struct file_system *fs);
	int (*umount)(struct file_system *fs);
	void (*getsize)(struct file_system *fs, size_t *total, size_t *idle);
	int (*getpath)(struct file_path *path);
	void (*putpath)(struct file_path *path);
	void (*suspend)(struct file_system *fs);
	void (*resume)(struct file_system *fs);
};

/* excluding the mnt, return the real path inside the target FS  */
static inline const char *fspath_of(
	struct file_system *fs, const char *path)
{
	if (*path != '/')
		path--;

	return path + strlen(fs->mnt.path);
}

/* check if the '/' exists in the tail */
static inline int fspath_isdir(const char *path)
{
	int l = strnlen(path, FS_PATH_MAX);

	return !l || (path[l - 1] == '/');
}

static inline char *dirname(char *path)
{
	int i = 0;
	unsigned int l = 0;

	if (!path || *path == 0)
		return NULL;

	l = strlen(path);

	while (l && (path[l - 1] == '/')) {
		path[l - 1] = 0;
		l--;
	}

	for (i = l - 1; i >= 0; i--) {
		if (path[i] == '/') {
			path[i] = 0;
			break;
		}
	}

	return (i < 0 || *path == 0) ? "/" : path;
}

/*
 * Helper function to format a directory entry into the user buffer.
 * This provides a unified way for all filesystems to populate dirent structures.
 *
 * Parameters:
 *   d_ptr:    Pointer to pointer of dirent buffer (will be advanced)
 *   buflen:   Pointer to remaining buffer size (will be decreased)
 *   name:     File/directory name
 *   type:     Entry type (DT_REG, DT_DIR, etc.)
 *   off:      Directory offset for next entry
 *
 * Returns:    Number of bytes written on success (reclen)
 *             -ENOSPC if buffer is too small
 */
static inline ssize_t fs_format_dirent(
	struct dirent **d_ptr, size_t *buflen,
	const char *name, uint8_t type, uint64_t off)
{
	struct dirent *d = *d_ptr;
	size_t name_len = strlen(name);
	size_t reclen = sizeof(struct dirent) + name_len + 1;

	reclen = roundup(reclen, sizeof(long));

	if (reclen > *buflen)
		return -ENOSPC;

	d->d_off = off;
	d->d_reclen = reclen;
	d->d_type = type;
	memcpy(d->d_name, name, name_len);
	d->d_name[name_len] = 0;

	*d_ptr = (struct dirent *)((char *)d + reclen);
	*buflen -= reclen;
	return reclen;
}

/*
 * Update file timestamps.
 * Common helper used by devfs, tmpfs, and other sub-filesystems.
 */
static inline void fs_update_time(time_t *atime,
	time_t *mtime, time_t *ctime)
{
	time_t tsec = 0;

	get_systime(&tsec, NULL);

	if (atime)
		*atime = tsec;
	if (mtime)
		*mtime = tsec;
	if (ctime)
		*ctime = tsec;
}

void fs_create(const char *name);

int alloc_kpath(const char *src, struct file_path *p);
int alloc_path(const char *src, struct file_path *p);
void free_path(struct file_path *p);

/* mount / unmount the known FS */
int fs_mount(struct file_system *fs);
int fs_umount(struct file_system *fs);

/* common FS path handling  */
int fs_getpath(struct file_path *path);
void fs_putpath(struct file_path *path);

/* suspend / resume all sub-file-system */
void fs_suspend(void);
void fs_resume(void);

/* reference counter will be increased / decreased */
struct file_system *fs_get(const char *path);
void fs_put(struct file_system *fs);

#ifdef __cplusplus
}
#endif

#endif
