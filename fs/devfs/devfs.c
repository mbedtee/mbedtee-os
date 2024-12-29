// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * devfs
 */

#include <of.h>
#include <fs.h>
#include <trace.h>
#include <init.h>
#include <ktime.h>
#include <devfs.h>
#include <strmisc.h>
#include <thread.h>
#include <kmalloc.h>

#define DEVFS_ATTR_RO	0x01
#define DEVFS_ATTR_VOL	0x08
#define DEVFS_ATTR_DIR	0x10
#define DEVFS_ATTR_DEV	0x20

struct devfs_node {
	/* current reference counter */
	int refc;
	short attr;
	/* number of sub-nodes (for directory only) */
	short sub_nodes;
	/* idx @ its directory */
	unsigned long idx;
	/* name of this node */
	char name[DEV_MAX_NAME];
	/* node in its directory */
	struct list_head node;
	/* @ which directory */
	struct devfs_node *parent;
	/* head of its nodes (for directory only) */
	struct list_head nodes;

	time_t atime; /* time of last access */
	time_t mtime; /* time of last modification */
	time_t ctime; /* time of last status change */

	void *priv;
};

struct devfs {
	struct mutex lock;
	struct devfs_node root;
};

#define lock_devfs(fs) mutex_lock(&((fs)->lock))
#define unlock_devfs(fs) mutex_unlock(&((fs)->lock))

static inline struct devfs *file2devfs(struct file *f)
{
	return (struct devfs *)f->fs->priv;
}

static void devfs_update_time(time_t *atime,
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

static struct devfs_node *devfs_find_node(
	struct devfs_node *dir,
	const char *name)
{
	struct devfs_node *n = NULL;

	list_for_each_entry(n, &dir->nodes, node) {
		if (!strcmp(n->name, name))
			return n;
	}

	return NULL;
}

static struct devfs_node *devfs_create_node(
	struct devfs_node *dir,
	const char *name)
{
	struct devfs_node *n = NULL;
	struct devfs_node *t = NULL;
	struct devfs_node *f = NULL;

	n = kzalloc(sizeof(struct devfs_node));
	if (n == NULL)
		return NULL;

	n->refc = 1;
	n->parent = dir;
	strlcpy(n->name, name, sizeof(n->name));
	INIT_LIST_HEAD(&n->nodes);

	dir->refc++;
	dir->sub_nodes++;

	devfs_update_time(&n->atime, &n->mtime, &n->ctime);

	t = list_last_entry_or_null(&dir->nodes, struct devfs_node, node);
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
	return n;
}

static void devfs_put_node(struct devfs *fs,
	struct devfs_node *n)
{
	struct devfs_node *dir = NULL;

	if (n && (n != &fs->root) && (--n->refc == 0)) {
		dir = n->parent;
		dir->sub_nodes--;
		list_del(&n->node);
		kfree(n);

		while (dir && (dir != &fs->root)) {
			n = dir->parent;
			if (--dir->refc == 0) {
				list_del(&dir->node);
				kfree(dir);
				dir = n;
				if (dir)
					dir->sub_nodes--;
			} else
				break;
		}
	}
}

static struct devfs_node *devfs_get_node(
	struct devfs *fs,
	const char *p)
{
	int len = 0;
	char name[DEV_MAX_NAME];
	struct devfs_node *n = &fs->root;

	while (*p == '/')
		p++;

	for (;;) {
		if (*p && *p != '/') {
			name[len++] = *p++;
		} else {
			if (len == 0)
				break;
			name[len] = 0;
			n = devfs_find_node(n, name);
			if (n == NULL) {
				LMSG("%s not exist\n\n", name);
				break;
			}
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

static int devfs_mknodes(struct devfs *fs,
	const char *p, struct devfs_node **ppn, int isdir)
{
	char name[DEV_MAX_NAME];
	int len = 0, ret = -1, isfinal = false;
	struct devfs_node *dir = &fs->root, *n = NULL;

	while (*p == '/')
		p++;

	for (;;) {
		if (*p && *p != '/') {
			name[len++] = *p++;
			if ((len == DEV_MAX_NAME) &&
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

			n = devfs_find_node(dir, name);

			if (n == NULL && !isfinal) {
				n = devfs_create_node(dir, name);
				if (n == NULL) {
					ret = -ENOMEM;
					goto out;
				}
				n->attr |= DEVFS_ATTR_DIR;
			}

			if (n != NULL && isfinal) {
				ret = -EEXIST;
				goto out;
			}

			if (isfinal) {
				if (!(dir->attr & DEVFS_ATTR_DIR)) {
					ret = -ENOTDIR;
					goto out;
				}

				n = devfs_create_node(dir, name);
				if (n == NULL) {
					ret = -ENOMEM;
					goto out;
				}

				n->attr |= isdir ? DEVFS_ATTR_DIR : DEVFS_ATTR_DEV;

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

int devfs_create(struct file_system *pfs,
	struct device *dev)
{
	int ret = -1;
	struct devfs *fs = pfs->priv;
	struct devfs_node *n = NULL;
	const char *p = fspath_of(pfs, dev->path);

	if (strlen(p) >= DEV_MAX_NAME)
		return -ENAMETOOLONG;

	if (fspath_isdir(p))
		return -EISDIR;

	lock_devfs(fs);

	ret = devfs_mknodes(fs, p, &n, false);
	if (ret != 0)
		goto out;

	n->priv = dev;
	dev->fs_data = n;

out:
	unlock_devfs(fs);
	return ret;
}

void devfs_remove(struct file_system *pfs,
	struct device *dev)
{
	struct devfs *fs = pfs->priv;

	lock_devfs(fs);
	devfs_put_node(fs, dev->fs_data);
	unlock_devfs(fs);
}

static int devfs_security_check(const char *name)
{
	struct thread *t = current;
	struct process *proc = t->proc;

	/*
	 * privileged, permitted
	 */
	if (proc->c->privilege)
		return 0;

	/*
	 * null is permitted for all
	 */
	if (strcmp("/dev/null", name) == 0)
		return 0;

	/*
	 * permission permitted
	 */
	if (strstr_delimiter(proc->c->dev_acl, name, ','))
		return 0;

	WMSG("%s access %s denied\n", t->name, name);
	return -EACCES;
}

static int devfs_getpath(struct file_path *p)
{
	char *dst = NULL;
	int name_len = strlen(p->path) + 1;

	if (name_len > DEV_MAX_NAME)
		return -ENAMETOOLONG;

	if (devfs_security_check(p->path))
		return -EACCES;

	dst = kmalloc(name_len);
	if (dst == NULL)
		return -ENOMEM;

	strlcpy(dst, p->path, name_len);
	p->path = dst;
	return 0;
}

static void devfs_putpath(struct file_path *p)
{
	kfree(p->path);
	p->path = NULL;
}

static int devfs_open(struct file *f, mode_t mode, void *arg)
{
	int flags = f->flags;
	int ret = -1, isdir = false;
	struct devfs_node *n = NULL;
	struct device *dev = NULL;
	struct devfs *fs = file2devfs(f);

	lock_devfs(fs);
	n = devfs_get_node(fs, f->path);
	if (n == NULL) {
		ret = -ENOENT;
		goto out;
	}

	if (n->attr & DEVFS_ATTR_DEV) {
		isdir = fspath_isdir(f->path);
		if (isdir | (flags & O_DIRECTORY)) {
			ret = -ENOTDIR;
			goto out;
		}

		dev = n->priv;
		f->dev = dev;

		if (dev->fops->open == NULL) {
			ret = -ENXIO;
			goto out;
		}

		unlock_devfs(fs);
		ret = dev->fops->open(f, mode, arg);
		if (ret == 0)
			return ret;
		lock_devfs(fs);
	} else {
		if (flags & (O_ACCMODE | O_CREAT)) {
			ret = -EISDIR;
			goto out;
		}

		if (flags & (O_TRUNC | O_APPEND)) {
			ret = -EISDIR;
			goto out;
		}

		f->flags |= O_DIRECTORY;
		f->priv = n;
		f->dev = NULL;
		ret = 0;
	}

out:
	if (ret != 0)
		devfs_put_node(fs, n);
	unlock_devfs(fs);
	return ret;
}

static int devfs_close(struct file *f)
{
	int ret = -1;
	struct device *dev = f->dev;
	struct devfs *fs = file2devfs(f);
	struct devfs_node *n = NULL;

	if (dev) {
		n = dev->fs_data;

		if (dev->fops->close == NULL)
			return -ENXIO;

		ret = dev->fops->close(f);
	} else {
		/* directory ? */
		n = f->priv;

		if (!n || !(n->attr & DEVFS_ATTR_DIR))
			return -EBADF;
		ret = 0;
	}

	lock_devfs(fs);
	devfs_put_node(fs, n);
	unlock_devfs(fs);

	return ret;
}

static ssize_t devfs_read(struct file *f, void *buf, size_t cnt)
{
	ssize_t ret = -1;
	struct device *dev = f->dev;

	if (dev == NULL)
		return -EBADF;

	if (dev->fops->read == NULL)
		return -ENXIO;

	ret = dev->fops->read(f, buf, cnt);
	if (ret > 0) {
		struct devfs_node *n = dev->fs_data;

		devfs_update_time(&n->mtime, NULL, NULL);
	}

	return ret;
}

static ssize_t devfs_write(struct file *f, const void *buf, size_t cnt)
{
	ssize_t ret = -1;
	struct device *dev = f->dev;

	if (dev == NULL)
		return -EBADF;

	if (dev->fops->write == NULL)
		return -ENXIO;

	ret = dev->fops->write(f, buf, cnt);
	if (ret > 0) {
		struct devfs_node *n = dev->fs_data;

		devfs_update_time(NULL, &n->mtime, &n->ctime);
	}

	return ret;
}

static int devfs_mmap(struct file *f, struct vm_struct *vm)
{
	struct device *dev = f->dev;

	if (dev == NULL)
		return -EBADF;

	if (dev->fops->mmap == NULL)
		return -ENXIO;

	return dev->fops->mmap(f, vm);
}

static int devfs_ioctl(struct file *f, int request, unsigned long arg)
{
	struct device *dev = f->dev;

	if (dev == NULL)
		return -EBADF;

	if (dev->fops->ioctl == NULL)
		return -ENXIO;

	return dev->fops->ioctl(f, request, arg);
}

static int devfs_poll(struct file *f, struct poll_table *wait)
{
	struct device *dev = f->dev;

	if (dev == NULL)
		return -EBADF;

	if (dev->fops->poll == NULL)
		return -ENXIO;

	return dev->fops->poll(f, wait);
}

static off_t devfs_seekdir(struct file *f, off_t off, int whence)
{
	int ret = -EINVAL, ops = 0;
	struct devfs_node *dir = f->priv;
	struct devfs *fs = file2devfs(f);
	struct devfs_node *n = NULL;

	if (dir == NULL)
		return -EBADF;

	lock_devfs(fs);

	n = list_last_entry_or_null(&dir->nodes, struct devfs_node, node);

	ops = (whence != SEEK_SET) ? f->pos : off;

	if (n == NULL || n->idx < ops)
		goto out;

	list_for_each_entry(n, &dir->nodes, node) {
		if (n->idx >= ops)
			break;
	}

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
	f->pos = n->idx;
	ret = n->idx;
out:
	unlock_devfs(fs);
	return ret;
}

static off_t devfs_lseek(struct file *f, off_t off, int whence)
{
	struct device *dev = f->dev;

	if (dev == NULL)
		return devfs_seekdir(f, off, whence);

	if (dev->fops->lseek == NULL)
		return -ENXIO;

	return dev->fops->lseek(f, off, whence);
}

static int devfs_truncate(struct file *f, off_t length)
{
	int ret = -1;
	struct device *dev = f->dev;

	if (dev == NULL)
		return -EBADF;

	if (dev->fops->ftruncate == NULL)
		return -ENXIO;

	ret = dev->fops->ftruncate(f, length);
	if (ret == 0) {
		struct devfs_node *n = dev->fs_data;

		devfs_update_time(NULL, &n->mtime, &n->ctime);
	}

	return ret;
}

static int devfs_fstat(struct file *f, struct stat *st)
{
	struct device *dev = f->dev;
	struct devfs_node *n = NULL;

	if (dev != NULL) {
		n = dev->fs_data;

		if (dev->fops->fstat != NULL)
			return dev->fops->fstat(f, st);

		st->st_mode = S_IFREG;
	} else {
		n = f->priv;
		st->st_mode = S_IFDIR;
	}

	st->st_size = 0;
	st->st_blksize = 0;
	st->st_blocks = 0;
	st->st_atime = n->atime;
	st->st_mtime = n->mtime;
	st->st_ctime = n->ctime;

	return 0;
}

static ssize_t devfs_readdir(struct file *f, struct dirent *d, size_t count)
{
	ssize_t rdbytes = -1, pos = 0;
	ssize_t reclen = 0, dsize = 0;
	struct devfs *fs = file2devfs(f);
	struct devfs_node *dir = f->priv;
	struct devfs_node *n = NULL;
	struct devfs_node *last = NULL;

	if ((dir == NULL) || f->dev)
		return -EBADF;

	if (d == NULL)
		return -EINVAL;

	lock_devfs(fs);

	last = list_last_entry_or_null(&dir->nodes, struct devfs_node, node);
	if (!last || last->idx < f->pos)
		goto out;

	list_for_each_entry(n, &dir->nodes, node) {
		if (n->idx >= f->pos)
			break;
	}

	dsize = sizeof(d->d_type) + sizeof(d->d_reclen) + sizeof(d->d_off);

	while (n && (&n->node != &dir->nodes)) {
		rdbytes = strlen(n->name) + 1;
		reclen = roundup(rdbytes + dsize, (ssize_t)BYTES_PER_LONG);
		if (pos + reclen > count)
			break;
		d->d_type = (n->attr & DEVFS_ATTR_DEV) ? DT_CHR : DT_DIR;
		d->d_reclen = reclen;
		memcpy(d->d_name, n->name, rdbytes);

		pos += reclen;

		if (n != last) {
			n = list_next_entry(n, node);
			f->pos = d->d_off = n->idx;
		} else {
			f->pos = d->d_off = LONG_MAX;
			break;
		}

		d = (void *)d + reclen;
	}

out:
	unlock_devfs(fs);
	return pos;
}

static inline int devfs_mkdir(struct file_system *pfs, const char *path, mode_t mode)
{
	int ret = -1;
	struct devfs *fs = pfs->priv;
	struct devfs_node *n = NULL;

	lock_devfs(fs);

	ret = devfs_mknodes(fs, path, &n, true);

	unlock_devfs(fs);
	return ret;
}

static inline int devfs_rmdir(struct file_system *pfs, const char *path)
{
	int ret = -1;
	struct devfs *fs = pfs->priv;
	struct devfs_node *n = NULL;

	if (!path)
		return -EINVAL;

	lock_devfs(fs);

	n = devfs_get_node(fs, path);
	if (n == NULL) {
		ret = -ENOENT;
		goto out;
	}

	if (!(n->attr & DEVFS_ATTR_DIR)) {
		ret = -ENOTDIR;
		goto out;
	}

	/* check current DIR empty or not */
	if (!list_empty(&n->nodes)) {
		ret = -ENOTEMPTY;
		goto out;
	}

	/* mount point is not removable */
	if (n->attr & DEVFS_ATTR_VOL) {
		ret = -EBUSY;
		goto out;
	}

	devfs_put_node(fs, n);

out:
	devfs_put_node(fs, n);
	unlock_devfs(fs);
	return ret;
}

static const struct file_operations devfs_ops = {
	.open = devfs_open,
	.close = devfs_close,
	.read = devfs_read,
	.write = devfs_write,
	.mmap = devfs_mmap,
	.ioctl = devfs_ioctl,
	.poll = devfs_poll,

	.lseek = devfs_lseek,
	.ftruncate = devfs_truncate,
	.fstat = devfs_fstat,
	.rename = NULL,
	.unlink = NULL,

	.readdir = devfs_readdir,
	/*
	 * .mkdir = devfs_mkdir,
	 * .rmdir = devfs_rmdir,
	 */
	.mkdir = NULL,
	.rmdir = NULL,
};

static int devfs_mount(struct file_system *pfs)
{
	struct devfs *fs = NULL;

	fs = kzalloc(sizeof(struct devfs));
	if (fs == NULL)
		return -ENOMEM;

	mutex_init(&fs->lock);

	fs->root.name[0] = '/';
	fs->root.refc = 1;
	fs->root.parent = NULL;
	fs->root.attr |= DEVFS_ATTR_DIR | DEVFS_ATTR_VOL;
	INIT_LIST_HEAD(&fs->root.node);
	INIT_LIST_HEAD(&fs->root.nodes);
	devfs_update_time(&fs->root.atime,
		&fs->root.mtime, &fs->root.ctime);
	pfs->fops = &devfs_ops;
	pfs->priv = fs;
	pfs->type = "devfs";

	return 0;
}

static void suspend_dir(struct devfs_node *dir)
{
	int ret = -1;
	struct devfs_node *n = NULL;
	struct device *dev = NULL;

	list_for_each_entry_reverse(n, &dir->nodes, node) {
		if (n->attr & DEVFS_ATTR_DIR)
			suspend_dir(n);
		else {
			dev = n->priv;
			if (dev->sops && dev->sops->suspend) {
				IMSG("suspend %s\n", dev->path);
				ret = dev->sops->suspend(dev);
				if (ret)
					EMSG("suspend %s error\n", dev->path);
			}
		}
	}
}

static void resume_dir(struct devfs_node *dir)
{
	int ret = -1;
	struct devfs_node *n = NULL;
	struct device *dev = NULL;

	list_for_each_entry(n, &dir->nodes, node) {
		if (n->attr & DEVFS_ATTR_DIR)
			resume_dir(n);
		else {
			dev = n->priv;
			if (dev->sops && dev->sops->resume) {
				IMSG("resume %s\n", dev->path);
				ret = dev->sops->resume(dev);
				if (ret)
					EMSG("resume %s error\n", dev->path);
			}
		}
	}
}

static void devfs_suspend(struct file_system *pfs)
{
	struct devfs *fs = pfs->priv;

	/*
	 * suspend the all sub devices
	 * no race condition at this moment
	 */
	suspend_dir(&fs->root);
}

static void devfs_resume(struct file_system *pfs)
{
	struct devfs *fs = pfs->priv;

	/*
	 * resume the all sub devices
	 * no race condition at this moment
	 */
	resume_dir(&fs->root);
}

static int dev_null_open(struct file *f, mode_t mode, void *arg)
{
	return 0;
}

static int dev_null_close(struct file *f)
{
	return 0;
}

static ssize_t dev_null_read(struct file *f,
	void *buf, size_t count)
{
	return 0;
}

static ssize_t dev_null_write(struct file *f,
	const void *buf, size_t count)
{
	return count;
}

static const struct file_operations dev_null_fops = {
	.open = dev_null_open,
	.close = dev_null_close,
	.read = dev_null_read,
	.write = dev_null_write,
};

static void __init dev_null_init(void)
{
	struct device *dev = kzalloc(sizeof(*dev));

	dev->fops = &dev_null_fops;
	dev->path = "/dev/null";

	device_register(dev);
}


static struct file_system devfs_root = {
	.name = "devfs",
	.mnt = {"/dev", 0, 0},
	.mount = devfs_mount,
	.getpath = devfs_getpath,
	.putpath = devfs_putpath,
	.suspend = devfs_suspend,
	.resume = devfs_resume,
	.fops = &devfs_ops,
};

static void __init devfs_init(void)
{
	assert(fs_mount(&devfs_root) == 0);

	dev_null_init();
}
EARLY_INIT_ARCH(devfs_init);
