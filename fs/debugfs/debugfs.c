// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * debugfs (based on TMPFS)
 */

#include <of.h>
#include <fs.h>
#include <tfs.h>
#include <vma.h>
#include <trace.h>
#include <init.h>
#include <timer.h>
#include <ktime.h>
#include <strmisc.h>
#include <uaccess.h>
#include <process.h>
#include <vmalloc.h>
#include <mqueue.h>
#include <signal.h>
#include <syscall.h>
#include <kmalloc.h>

#include <debugfs.h>

static struct tfs debugfs_tfs;

static struct tfs_node *debugfs_alloc_node(struct tfs *fs)
{
	struct debugfs_fnode *d = kzalloc(sizeof(*d));

	if (d == NULL)
		return NULL;

	return &d->node;
}

static void debugfs_free_node(struct tfs_node *n)
{
	struct debugfs_fnode *d = debugfs_fnode_of(n);

	kfree(d);
}

static int debugfs_do_open(struct tfs *fs,
	struct tfs_node *n, int isdir, struct file *f)
{
	int ret = -1;
	int flags = f->flags;

	tfs_lock_node(n);

	if (flags & O_EXCL) {
		ret = -EEXIST;
		goto out;
	}

	if (n->attr & TFS_ATTR_DIR) {
		if (flags & (O_ACCMODE | O_CREAT)) {
			ret = -EISDIR;
			goto out;
		}

		if (flags & (O_TRUNC | O_APPEND)) {
			ret = -EISDIR;
			goto out;
		}
		f->flags |= O_DIRECTORY;
	} else if (isdir | (flags & O_DIRECTORY)) {
		ret = -ENOTDIR;
		goto out;
	}

	ret = tfs_security_check(fs, n);
	if (ret != 0)
		goto out;

out:
	tfs_unlock_node(n);
	return ret;
}

static int debugfs_open(struct file *f,
	mode_t mode, void *unused)
{
	int ret = -1;
	struct tfs *fs = file2tfs(f);
	struct debugfs_file *df = NULL;
	struct debugfs_fnode *dn = NULL;

	if (f->flags & O_CREAT)
		return -EINVAL;

	df = kzalloc(sizeof(*df));
	if (df == NULL)
		return -ENOMEM;

	tfs_lock(fs);

	df->n = tfs_get_node(fs, f->path);
	if (df->n == NULL) {
		ret = -ENOENT;
		goto out;
	}

	ret = debugfs_do_open(fs, df->n, fspath_isdir(f->path), f);
	if (ret != 0)
		goto out;

	if (df->n->attr & TFS_ATTR_ARC) {
		dn = debugfs_fnode_of(df->n);
		if (dn->fops->open) {
			ret = dn->fops->open(df);
			if (ret != 0)
				goto out;
		}
	}

	f->priv = df;
	ret = 0;

out:
	tfs_unlock(fs);
	if (ret != 0) {
		tfs_put_node(fs, df->n);
		kfree(df);
	}
	return ret;
}

static int debugfs_close(struct file *f)
{
	struct debugfs_file *df = f->priv;
	struct debugfs_fnode *dn = debugfs_fnode_of(df->n);
	struct tfs *fs = file2tfs(f);

	if (df->n->attr & TFS_ATTR_ARC) {
		dn = debugfs_fnode_of(df->n);
		if (dn->fops->close != NULL)
			dn->fops->close(df);
	}

	tfs_lock(fs);
	tfs_put_node(fs, df->n);
	tfs_unlock(fs);

	kfree(df);
	return 0;
}

static void debugfs_rmdir(struct tfs *fs,
	struct tfs_node *dir)
{
	struct tfs_node *n = NULL;
	off_t pos = 0, rdbytes = 0;
	unsigned char dbuf[256];
	struct dirent *d = (struct dirent *)dbuf;

	rdbytes = tfs_readdir(fs, dir, &pos, d, sizeof(dbuf));

	while (rdbytes > 0) {
		n = tfs_lookup_node(dir, d->d_name);

		assert(n != NULL);

		if (n->attr & TFS_ATTR_ARC) {
			list_del(&n->node);
			tfs_put_node(fs, n);
		} else {
			debugfs_rmdir(fs, n);
		}

		rdbytes -= d->d_reclen;
		d = (void *)d + d->d_reclen;
	}

	list_del(&dir->node);
	tfs_put_node(fs, dir);
}

int debugfs_remove(const char *path)
{
	int ret = -1;
	struct tfs_node *n = NULL;
	struct tfs *fs = &debugfs_tfs;

	tfs_lock(fs);

	n = tfs_get_node(fs, path);
	if (n == NULL) {
		ret = -ENOENT;
		goto out;
	}

	if (n->attr & TFS_ATTR_ARC) {
		list_del(&n->node);
		tfs_put_node(fs, n);
	} else {
		debugfs_rmdir(fs, n);
	}

	ret = 0;

out:
	tfs_put_node(fs, n);
	tfs_unlock(fs);
	return ret;
}

int debugfs_create(const char *path,
	const struct debugfs_fops *fops)
{
	int ret = -1;
	struct tfs_node *n = NULL;
	struct debugfs_fnode *dn = NULL;
	struct tfs *fs = &debugfs_tfs;

	if (fspath_isdir(path))
		return -EISDIR;

	tfs_lock(fs);

	ret = tfs_make_node(fs, path, &n, false);
	if (ret != 0)
		goto out;

	dn = debugfs_fnode_of(n);

	dn->fops = fops;

	ret = 0;

out:
	tfs_unlock(fs);
	return ret;
}

int debugfs_create_dir(const char *path)
{
	int ret = -1;
	struct tfs_node *n = NULL;
	struct tfs *fs = &debugfs_tfs;

	tfs_lock(fs);

	ret = tfs_make_node(fs, path, &n, true);

	tfs_unlock(fs);
	return ret;
}

void debugfs_printf(struct debugfs_file *d, const char *fmt, ...)
{
	int len = 0;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(d->buf + d->cnt,
		d->size - d->cnt, fmt, ap);
	va_end(ap);

	d->required += len;

/* add 1 bytes for terminal null byte */
	if (d->cnt + len + 1 < d->size) {
		d->cnt += len;
		return;
	}

	d->cnt = d->size;
}

static int debugfs_alloc(struct debugfs_file *d)
{
	if (d->buf)
		kvfree(d->buf);

	/* target might be growing..., so add a page-size */
	d->size = d->required + PAGE_SIZE;
	d->cnt = d->required = 0;
	d->buf = kmalloc(d->size);

	if (!d->buf)
		d->buf = vmalloc(d->size);

	return d->buf ? 0 : -ENOMEM;
}

static void debugfs_free(struct debugfs_file *d)
{
	d->pos = 0;
	d->cnt = 0;
	d->required = 0;

	kvfree(d->buf);
	d->buf = NULL;
}

static ssize_t debugfs_read(struct file *f, void *buf, size_t cnt)
{
	ssize_t ret = 0;
	struct debugfs_file *d = f->priv;
	struct tfs_node *n = d->n;
	struct debugfs_fnode *dn = debugfs_fnode_of(n);

	if (buf == NULL)
		return -EINVAL;

	tfs_lock_node(n);

	if (d->buf == NULL) {
		ret = debugfs_alloc(d);
		if (ret != 0)
			goto out;
	}

	if (d->cnt == 0) {
		do {
			ret = dn->fops->read(d);
			if (ret != 0)
				goto out;

			/* buffer is enough */
			if (d->size != d->cnt) {
				/*
				 * add 1 bytes for terminal null byte
				 * this helps the userspace to do the EOF check
				 */
				d->cnt++;
				break;
			}

			ret = debugfs_alloc(d);
			if (ret != 0)
				goto out;
		} while (1);
	}

	ret = min(cnt, d->cnt);

	memcpy(buf, d->buf + d->pos, ret);

	d->cnt -= ret;
	d->pos += ret;

	if (d->cnt == 0)
		debugfs_free(d);

out:
	tfs_update_time(&n->atime, NULL, NULL);
	if (ret < 0)
		debugfs_free(d);
	tfs_unlock_node(n);
	return ret;
}

static ssize_t debugfs_write(struct file *f, const void *buf, size_t cnt)
{
	ssize_t ret = -EINVAL;
	struct debugfs_file *d = f->priv;
	struct tfs_node *n = d->n;
	struct debugfs_fnode *dn = debugfs_fnode_of(n);

	if (buf == NULL)
		return ret;

	if (dn->fops->write == NULL)
		return -ENXIO;

	tfs_lock_node(n);

	ret = dn->fops->write(d, buf, cnt);

	tfs_update_time(NULL, &n->mtime, &n->ctime);

	tfs_unlock_node(n);

	return ret;
}

static int debugfs_fstat(struct file *f, struct stat *st)
{
	struct debugfs_file *df = f->priv;
	struct tfs_node *n = df->n;

	if (st == NULL)
		return -EINVAL;

	tfs_lock_node(n);

	st->st_blksize = 1;
	st->st_blocks = df->cnt;
	st->st_size = df->cnt;

	if (n->attr & TFS_ATTR_DIR)
		st->st_mode = S_IFDIR;
	else
		st->st_mode = S_IFREG;

	st->st_atime = n->atime;
	st->st_mtime = n->mtime;
	st->st_ctime = n->ctime;

	tfs_unlock_node(n);
	return 0;
}

static off_t debugfs_seekdir(struct file *f, off_t off, int whence)
{
	int ret = -EINVAL;
	struct tfs *fs = file2tfs(f);
	struct debugfs_file *df = f->priv;

	tfs_lock(fs);
	ret = tfs_seekdir(fs, df->n, &f->pos, off, whence);
	tfs_unlock(fs);

	return ret;
}

static ssize_t debugfs_readdir(struct file *f, struct dirent *d, size_t cnt)
{
	ssize_t rdbytes = -1;
	struct tfs *fs = file2tfs(f);
	struct debugfs_file *df = f->priv;

	if (d == NULL)
		return -EINVAL;

	tfs_lock(fs);
	rdbytes = tfs_readdir(fs, df->n, &f->pos, d, cnt);
	tfs_unlock(fs);

	return rdbytes;
}

static const struct file_operations debugfs_fnode_ops = {
	.open = debugfs_open,
	.close = debugfs_close,
	.read = debugfs_read,
	.write = debugfs_write,

	.fstat = debugfs_fstat,
	.readdir = debugfs_readdir,
	.lseek = debugfs_seekdir
};

static struct tfs debugfs_tfs = {
	.alloc = debugfs_alloc_node,
	.free = debugfs_free_node,
	.security_check = tfs_check
};

static struct file_system debugfs_fs = {
	/* based on the tmpfs */
	.name = "dbgfs",
	.mnt = {"/debug", 0, 0},
	.mount = tfs_mount,
	.umount = tfs_umount,
	.getpath = tfs_getpath,
	.putpath = tfs_putpath,
	.fops = &debugfs_fnode_ops,

	/* independent tmpfs instance */
	.priv = &debugfs_tfs,
};

static void __init debugfs_init(void)
{
	fs_mount(&debugfs_fs);
}
EARLY_INIT_ARCH(debugfs_init);
