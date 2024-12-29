/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * FS framework
 */

#ifndef _FS_H
#define _FS_H

#include <errno.h>
#include <string.h>

#include <trace.h>
#include <buddy.h>
#include <mutex.h>
#include <list.h>
#include <file.h>
#include <ktime.h>

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
	size_t (*getfree)(struct file_system *fs);
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

	if (path == NULL || *path == 0)
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

/* extract the directory and name from path */
static inline void fspath_directory_name(
	const char *path, char *directory, char *name)
{
	int i = 0;
	unsigned int l = strnlen(path, FS_PATH_MAX);

	if (l == 0)
		return;

	memcpy(directory, path, l + 1);

	if (directory[l - 1] == '/')
		directory[--l] = 0;

	for (i = l - 1; i >= 0; i--) {
		if (directory[i] == '/') {
			directory[i] = 0;
			break;
		}
	}

	memcpy(name, directory + i + 1, min(FS_NAME_MAX - 1, l - i));

	if (i < 0) /* root dir */
		directory[0] = 0;
}

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

#endif
