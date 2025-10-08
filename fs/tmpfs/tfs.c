// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * basic node operations of tmpfs
 */

#include <of.h>
#include <fs.h>
#include <vma.h>
#include <trace.h>
#include <init.h>
#include <timer.h>
#include <ktime.h>
#include <strmisc.h>
#include <thread.h>
#include <kmalloc.h>

#include <tfs.h>

struct tfs_node *tfs_lookup_node(
	struct tfs_node *dir,
	const char *name)
{
	struct tfs_node *n = NULL;

	list_for_each_entry(n, &dir->nodes, node) {
		if (!strcmp(n->name, name))
			return n;
	}

	return NULL;
}

static int tfs_init_node(
	struct tfs_node *dir,
	struct tfs_node *n,
	const char *name)
{
	struct tfs_node *t = NULL, *f = NULL;
	struct process *proc = current->proc;
	int namel = strlen(name) + 1;

	n->refc = 1;
	n->parent = dir;
	n->owner = proc->c;

	INIT_LIST_HEAD(&n->nodes);
	mutex_init(&n->lock);

	n->name = kmalloc(namel);
	if (n->name == NULL)
		return -ENOMEM;

	strlcpy(n->name, name, namel);

	dir->refc++;
	dir->sub_nodes++;
	tfs_update_time(&n->atime, &n->mtime, &n->ctime);

	t = list_last_entry_or_null(&dir->nodes, struct tfs_node, node);
	if (t != NULL) {
		n->idx = t->idx + 1;
		if (n->idx < ULONG_MAX) {
			list_add_tail(&n->node, &dir->nodes);
		} else { /* ? never meet ? */
			while (++n->idx) {
				list_for_each_entry(t, &dir->nodes, node) {
					if (t->idx == n->idx)
						break;
					if (t->idx > n->idx) {
						f = t;
						break;
					}
				}
				if (f != NULL)
					break;
			}
			list_add(&n->node, &f->node);
		}
	} else {
		n->idx = 0;
		list_add_tail(&n->node, &dir->nodes);
	}

	return 0;
}

int tfs_put_node(struct tfs *fs,
	struct tfs_node *n)
{
	struct tfs_node *dir = NULL;

	if (n && (n != fs->root) && (--n->refc == 0)) {
		list_del(&n->node);
		dir = n->parent;
		dir->sub_nodes--;

		mutex_destroy(&n->lock);

		kfree(n->name);

		fs->free(n);

		while (dir && (dir != fs->root)) {
			n = dir->parent;
			if (--dir->refc == 0) {
				list_del(&dir->node);
				mutex_destroy(&dir->lock);
				kfree(dir->name);
				fs->free(dir);
				dir = n;
				if (dir)
					dir->sub_nodes--;
			} else
				break;
		}

		return true;
	}

	return false;
}

struct tfs_node *tfs_get_node(
	struct tfs *fs, const char *p)
{
	int len = 0;
	char name[FS_NAME_MAX];
	struct tfs_node *n = fs->root;

	while (*p == '/')
		p++;

	for (;;) {
		if (*p && *p != '/') {
			name[len++] = *p++;
		} else {
			if (len == 0)
				break;
			name[len] = 0;
			n = tfs_lookup_node(n, name);
			if (n == NULL)
				break;
			while (*p == '/')
				p++;
			if (*p == '\0')
				break;
			len = 0;
		}
	}

	if (n != NULL)
		n->refc++;

	return n;
}

int tfs_make_node(struct tfs *fs,
	const char *p, struct tfs_node **ppn, int isdir)
{
	int len = 0, ret = -1, isfinal = false;
	char name[FS_NAME_MAX];
	struct tfs_node *dir = fs->root, *n = NULL;

	while (*p == '/')
		p++;

	for (;;) {
		if (*p && *p != '/') {
			name[len++] = *p++;
			if ((len == FS_NAME_MAX) &&
				(*p != '/') && (*p)) {
				ret = -ENAMETOOLONG;
				goto out;
			}
		} else {
			if (len == 0) {
				ret = -EINVAL;
				goto out;
			}
			name[len] = 0;

			while (*p == '/')
				p++;

			isfinal = (*p == 0);

			n = tfs_lookup_node(dir, name);

			if (n == NULL && !isfinal) {
				ret = -ENOENT;
				goto out;
			}
			if (n != NULL && isfinal) {
				ret = -EEXIST;
				goto out;
			}

			if (isfinal) {
				if (!(dir->attr & TFS_ATTR_DIR)) {
					ret = -ENOTDIR;
					goto out;
				}

				n = fs->alloc(fs);
				if (n == NULL) {
					ret = -ENOMEM;
					goto out;
				}

				ret = tfs_init_node(dir, n, name);
				if (ret) {
					fs->free(n);
					goto out;
				}

				n->attr = isdir ? TFS_ATTR_DIR : TFS_ATTR_ARC;
				break;
			}

			dir = n;
			len = 0;
		}
	}

	ret = 0;
	*ppn = n;

out:
	return ret;
}

ssize_t tfs_readdir(struct tfs *fs, struct tfs_node *dir,
	off_t *pos, struct dirent *d, size_t count)
{
	off_t offset = *pos;
	ssize_t rdbytes = -1, rd_off = 0;
	ssize_t reclen = 0, dsize = 0;
	struct tfs_node *n = NULL, *last = NULL;

	if (d == NULL)
		return -EINVAL;

	dsize = sizeof(d->d_type) + sizeof(d->d_reclen) + sizeof(d->d_off);

	last = list_last_entry_or_null(&dir->nodes, struct tfs_node, node);
	if (!last || last->idx < offset)
		return rd_off;

	list_for_each_entry(n, &dir->nodes, node) {
		if (n->idx >= offset)
			break;
	}

	while (n && (&n->node != &dir->nodes)) {
		rdbytes = strlen(n->name) + 1;
		reclen = roundup(rdbytes + dsize, (ssize_t)BYTES_PER_LONG);
		if (rd_off + reclen > count)
			break;

		d->d_type = (n->attr & TFS_ATTR_ARC) ? DT_CHR : DT_DIR;
		d->d_reclen = reclen;
		memcpy(d->d_name, n->name, rdbytes);
		rd_off += reclen;

		if (n != last) {
			n = list_next_entry(n, node);
			*pos = d->d_off = n->idx;
		} else {
			*pos = d->d_off = LONG_MAX;
			break;
		}

		d = (void *)d + reclen;
	}

	return rd_off;
}

off_t tfs_seekdir(struct tfs *fs, struct tfs_node *dir,
	off_t *pos, off_t off, int whence)
{
	struct tfs_node *n = NULL;
	int ret = -EINVAL, ops = 0;

	ops = (whence != SEEK_SET) ? *pos : off;

	list_for_each_entry(n, &dir->nodes, node) {
		if (n->idx >= ops)
			break;
	}

	if (!n || (&n->node == &dir->nodes))
		goto out;

	if (whence == SEEK_SET) {
		goto outset;
	} else if (whence == SEEK_CUR) {
		while (off && (&n->node != &dir->nodes)) {
			if (off < 0) {
				n = list_prev_entry(n, node);
				off++;
			} else {
				n = list_next_entry(n, node);
				off--;
			}
		}
	} else if (whence == SEEK_END) {
		while (off && (&n->node != &dir->nodes)) {
			if (off < 0) {
				n = list_prev_entry(n, node);
				off++;
			}
		}
	}

	if (off)
		goto out;

outset:
	*pos = n->idx;
	ret = n->idx;
out:
	return ret;
}

int tfs_check(struct tfs_node *n)
{
	struct process *proc = current->proc;

	/* privileged process always has the permission */
	if (proc->c->privilege)
		return 0;

	/* root directory is visible to all */
	if (n->owner == NULL)
		return 0;

	if (proc->c == n->owner)
		return 0;

	/* non-privileged proc can't access the file created by privileged process */
	if (n->owner->privilege)
		goto err;

	/*
	 * check if current TA has permission
	 * to access the target TA's file
	 */
	if (strstr_delimiter(proc->c->ipc_acl, n->owner->name, ','))
		return 0;

err:
	EMSG("%s->%s IPC permission??\n",
		proc->c->name, n->owner->name);
	return -EACCES;
}

int tfs_getpath(struct file_path *p)
{
	char *dst = NULL;
	int name_len = strlen(p->path) + 1;

	if (name_len > FS_NAME_MAX)
		return -ENAMETOOLONG;

	dst = kmalloc(name_len);
	if (dst == NULL)
		return -ENOMEM;

	strlcpy(dst, p->path, name_len);
	p->path = dst;
	return 0;
}

void tfs_putpath(struct file_path *p)
{
	kfree(p->path);
	p->path = NULL;
}

int tfs_umount(struct file_system *pfs)
{
	struct tfs *fs = pfs->priv;

	mutex_destroy(&fs->lock);
	mutex_destroy(&fs->root->lock);

	fs->free(fs->root);

	pfs->fops = NULL;
	pfs->priv = NULL;

	return 0;
}

int tfs_mount(struct file_system *pfs)
{
	struct tfs *fs = pfs->priv;
	const char *rootdir = "/";

	mutex_init(&fs->lock);

	fs->root = fs->alloc(fs);
	if (fs->root == NULL)
		return -ENOMEM;

	fs->root->name = (char *)rootdir;
	fs->root->refc = 1;
	fs->root->parent = NULL;
	fs->root->attr |= TFS_ATTR_DIR | TFS_ATTR_VOL | TFS_ATTR_RO;
	mutex_init(&fs->root->lock);
	INIT_LIST_HEAD(&fs->root->node);
	INIT_LIST_HEAD(&fs->root->nodes);
	tfs_update_time(&fs->root->atime,
		&fs->root->mtime, &fs->root->ctime);

	pfs->type = "tmpfs";
	pfs->priv = fs;

	return 0;
}
