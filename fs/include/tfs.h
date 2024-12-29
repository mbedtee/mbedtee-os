/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * TMPFS
 */

#ifndef _TMP_FS_H
#define _TMP_FS_H

#include <fs.h>

#define TFS_ATTR_RO			0x01
#define TFS_ATTR_VOL			0x08
#define TFS_ATTR_DIR			0x10
#define TFS_ATTR_ARC			0x20
#define TFS_ATTR_MASK			0x3F

#define tfs_lock(fs) mutex_lock(&((fs)->lock))
#define tfs_unlock(fs) mutex_unlock(&((fs)->lock))

#define tfs_lock_node(n) mutex_lock(&((n)->lock))
#define tfs_unlock_node(n) mutex_unlock(&((n)->lock))

/*
 * Each file or directory's information structure
 */
struct tfs_node {
	/* current reference counter */
	int refc;
	short attr;
	/* number of sub-nodes (for directory only) */
	short sub_nodes;
	/* idx @ its directory */
	unsigned long idx;

	/* head of its nodes (for directory only) */
	struct list_head nodes;
	/* node in its directory */
	struct list_head node;
	/* @ which directory */
	struct tfs_node *parent;

	/* name of this node */
	char *name;

	struct mutex lock;

	/* information of the owner */
	struct process_config *owner;

	time_t atime; /* time of last access */
	time_t mtime; /* time of last modification */
	time_t ctime; /* time of last status change */
};

struct tfs {
	/*
	 * Private Node operations for each fs instance
	 */
	struct tfs_node *(*alloc)(struct tfs *tfs);
	void (*free)(struct tfs_node *n);
	int (*security_check)(struct tfs_node *n);

	struct mutex lock;

	struct tfs_node *root;
};

struct tfs_node *tfs_lookup_node(struct tfs_node *dir,
	const char *name);
struct tfs_node *tfs_get_node(struct tfs *fs, const char *p);
int tfs_put_node(struct tfs *fs, struct tfs_node *n);
int tfs_make_node(struct tfs *fs, const char *p,
	struct tfs_node **ppn, int isdir);
ssize_t tfs_readdir(struct tfs *fs, struct tfs_node *dir,
	off_t *pos,	struct dirent *d, size_t cnt);
off_t tfs_seekdir(struct tfs *fs, struct tfs_node *dir,
	off_t *pos, off_t off, int whence);

/*
 * default common security check, each
 * instance can use itself check routine
 */
int tfs_check(struct tfs_node *n);

int tfs_mount(struct file_system *fs);
int tfs_umount(struct file_system *fs);

/* TMP FS path handling  */
int tfs_getpath(struct file_path *p);
void tfs_putpath(struct file_path *p);

static inline int tfs_security_check(struct tfs *fs,
	struct tfs_node *n)
{
	return fs->security_check(n);
}

static inline struct tfs *file2tfs(struct file *f)
{
	return (struct tfs *)f->fs->priv;
}

static inline void tfs_update_time(time_t *atime,
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

#endif
