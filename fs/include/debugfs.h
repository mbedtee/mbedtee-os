/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * debugfs
 */

#ifndef _DEBUGFS_H
#define _DEBUGFS_H

#include <tfs.h>

/*
 * debugfs file node based on tmpfs
 * lifecycle: create -> unlink
 */
struct debugfs_fnode {
	struct tfs_node node;
	const struct debugfs_fops *fops;
};

#define debugfs_fnode_of(n) container_of(n, struct debugfs_fnode, node)

/*
 * debugfs file information
 * lifecycle: open -> close
 */
struct debugfs_file {
/* dynamic allocated buffer */
	char *buf;
	size_t size;
/* count of bytes read from module */
	size_t cnt;
/* total required bytes when read from module */
	size_t required;
/* consumption position */
	off_t pos;

/* link to tfs node @ debugfs_fnode */
	struct tfs_node *n;
/* private data pointer assigned by each debugfs_open() instance */
	void *priv;
};

/*
 * debugfs operations
 */
struct debugfs_fops {
	int (*read)(struct debugfs_file *d);
	ssize_t (*write)(struct debugfs_file *d, const void *buf, size_t cnt);
	int (*open)(struct debugfs_file *d);
	int (*close)(struct debugfs_file *d);
};

#if defined(CONFIG_DEBUGFS)

__printf(2, 3) void debugfs_printf(struct debugfs_file *d, const char *fmt, ...);

/*
 * creates a directory
 */
int debugfs_create_dir(const char *path);

/*
 * creates a file with operations
 */
int debugfs_create(const char *path,
	const struct debugfs_fops *fops);

/*
 * recursively removes a directory or removes single file
 */
int debugfs_remove(const char *path);

#else

static inline void debugfs_printf(struct debugfs_file *d, const char *fmt, ...) {}
static inline int debugfs_create_dir(const char *path) {return -ENOTSUP; }
static inline int debugfs_create(const char *path,
	const struct debugfs_fops *fops) {return -ENOTSUP; }
static inline int debugfs_remove(const char *path) {return -ENOTSUP; }

#endif

#endif
