// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * File framework
 */

#include <errno.h>
#include <trace.h>
#include <device.h>
#include <thread.h>
#include <strmisc.h>
#include <sched.h>
#include <kmalloc.h>
#include <fs.h>
#include <vma.h>

#include <syscall.h>
#include <sys/mmap.h>

static struct atomic_num nrfiles = ATOMIC_INIT(0);

static inline void fd_pool_rbadd(
	struct fd_pool *p, struct rb_node **root)
{
	struct rb_node **ppn = root, *parent = NULL;
	struct fd_pool *tmp = NULL;
	unsigned int id = p->id;

	while (*ppn) {
		parent = *ppn;

		tmp = rb_entry_of(parent, struct fd_pool, node);

		if (id < tmp->id)
			ppn = &parent->left;
		else
			ppn = &parent->right;
	}

	rb_link_parent(&p->node, ppn, parent);
	rb_insert(&p->node, root);
}

/* alloc/deploy a fd bitmap pool */
static inline struct fd_pool *fd_pool_alloc(
	struct fdtab *fdt)
{
	struct fd_pool *p = NULL;

	p = kzalloc(sizeof(*p));
	if (p == NULL)
		return NULL;

	p->nbits = NUMFD_PER_POOL;

	p->id = fdt->nrpools++;
	fd_pool_rbadd(p, &fdt->pools);
	return p;
}

static inline void fd_pool_free(struct fdtab *fdt,
	struct fd_pool *p)
{
	fdt->nrpools--;
	rb_del(&p->node, &fdt->pools);
	kfree(p);
}

static int __fd_alloc(struct fdtab *fdt, bool lowest)
{
	int fd = -1, bmapid = 0;
	unsigned long flags = 0;
	struct fd_pool *p = NULL;

	spin_lock_irqsave(&fdt->lock, flags);

	if (lowest)
		p = rb_first_entry(fdt->pools, struct fd_pool, node);
	else
		p = rb_last_entry(fdt->pools, struct fd_pool, node);

again:
	if (p != NULL) {
		bmapid = bitmap_next_zero(p->bmap, NUMFD_PER_POOL, lowest ? 0 : p->next);
		if (bmapid == NUMFD_PER_POOL)
			bmapid = bitmap_next_zero(p->bmap, p->next, 0);

		p->next = bmapid + 1;

		fd = (p->id * NUMFD_PER_POOL) + bmapid;

		bitmap_set_bit(p->bmap, bmapid);

		if (--p->nbits == 0) {
			rb_del(&p->node, &fdt->pools);
			fd_pool_rbadd(p, &fdt->depletedpools);
		}
	} else {
		if (fdt->nrpools == PROCESS_FD_MAX / NUMFD_PER_POOL)
			fd = -EMFILE;
		else {
			p = fd_pool_alloc(fdt);
			if (p != NULL)
				goto again;
			fd = -ENOMEM;
		}
	}

	spin_unlock_irqrestore(&fdt->lock, flags);

	return fd;
}

static inline int fd_alloc_lowest(struct fdtab *fdt)
{
	return __fd_alloc(fdt, true);
}

static inline int fd_alloc(struct fdtab *fdt)
{
	return __fd_alloc(fdt, false);
}

static struct fd_pool *fd_pool_rbfind(struct rb_node **root, int id)
{
	struct rb_node *n = *root;
	struct fd_pool *p = NULL;

	while (n) {
		p = rb_entry_of(n, struct fd_pool, node);

		if (id == p->id)
			return p;

		if (id < p->id)
			n = n->left;
		else
			n = n->right;
	}

	return NULL;
}

static int fd_expand_set(struct fdtab *fdt, int fd)
{
	struct fd_pool *p = NULL;
	int poolid = fd / NUMFD_PER_POOL;
	int bmapid = fd & (NUMFD_PER_POOL - 1);

	if (poolid >= fdt->nrpools) {
		/* expand the fd table */
		while (poolid >= fdt->nrpools) {
			p = fd_pool_alloc(fdt);
			if (p == NULL)
				return -ENOMEM;
		}
	} else {
		p = fd_pool_rbfind(&fdt->pools, poolid);
		if (p == NULL)
			p = fd_pool_rbfind(&fdt->depletedpools, poolid);
	}

	if (p) {
		if (bitmap_bit_isset(p->bmap, bmapid))
			return -EBUSY;

		bitmap_set_bit(p->bmap, bmapid);

		p->next = bmapid + 1;
		if (--p->nbits == 0) {
			rb_del(&p->node, &fdt->pools);
			fd_pool_rbadd(p, &fdt->depletedpools);
		}
	}

	return 0;
}

static void __fd_free(struct fdtab *fdt, int fd)
{
	struct fd_pool *p = NULL;
	int poolid = fd / NUMFD_PER_POOL;
	int bmapid = fd & (NUMFD_PER_POOL - 1);
	struct rb_node **tree = &fdt->pools;

	p = fd_pool_rbfind(tree, poolid);
	if (p == NULL) {
		tree = &fdt->depletedpools;
		p = fd_pool_rbfind(tree, poolid);
	}

	if (p) {
		bitmap_clear_bit(p->bmap, bmapid);
		if (++p->nbits == NUMFD_PER_POOL) {
			if (poolid == fdt->nrpools - 1) {
				do {
					fd_pool_free(fdt, p);
					p = rb_last_entry(fdt->pools, struct fd_pool, node);
				} while (p && p->nbits == NUMFD_PER_POOL);
			}
		} else if (tree != &fdt->pools) {
			rb_del(&p->node, tree);
			fd_pool_rbadd(p, &fdt->pools);
		}
	}
}

static void fd_free(struct fdtab *fdt, int fd)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&fdt->lock, flags);
	__fd_free(fdt, fd);
	spin_unlock_irqrestore(&fdt->lock, flags);
}

static int file_alloc(struct file **ppf,
	const char *path, int fflags)
{
	struct file *f = NULL;
	struct file_system *fs = NULL;
	size_t path_len = strlen(path) + 1;

	fs = fs_get(path);
	if (fs == NULL)
		return -ENOENT;

	f = kzalloc(sizeof(*f) + path_len);
	if (f == NULL) {
		fs_put(fs);
		return -ENOMEM;
	}

	f->fs = fs;
	f->fops = fs->fops;
	f->flags = fflags;
	f->path = (char *)(f + 1);
	atomic_set(&f->refc, 1);
	strlcpy(f->path, fspath_of(fs, path), path_len);

	atomic_inc(&nrfiles);
	*ppf = f;
	return 0;
}

/* num of current-opening files */
int sys_numof_files(void)
{
	return atomic_read(&nrfiles);
}

static void file_free(struct file *f)
{
	atomic_dec(&nrfiles);
	fs_put(f->fs);
	kfree(f);
}

void file_put(struct file *f)
{
	assert(atomic_read(&f->refc) > 0);
	if (atomic_dec_return(&f->refc) == 0) {
		if (f->fops->close)
			f->fops->close(f);
		file_free(f);
	}
}

bool file_can_poll(struct file *f)
{
	void *pollfn = NULL;

	if (f->dev)
		pollfn = ((struct device *)f->dev)->fops->poll;
	else
		pollfn = f->fops->poll;

	return pollfn ? true : false;
}

int fdesc_alloc(struct file_desc **ppd,
	const char *path, int fflags)
{
	int ret = -1;
	struct file_desc *d = NULL;
	struct file *f = NULL;
	struct process *proc = current->proc;
	struct fdtab *fdt = &proc->fdt;

	ret = file_alloc(&f, path, fflags);
	if (ret != 0)
		return ret;

	d = kzalloc(sizeof(struct file_desc));
	if (d == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ret = fd_alloc(fdt);
	if (ret < 0)
		goto out;

	d->fd = ret;
	d->file = f;
	d->proc = proc;
	d->refc = 1;

	INIT_LIST_HEAD(&d->atcloses);
	rb_node_init(&d->node);

	*ppd = d;
	return 0;

out:
	file_free(f);
	kfree(d);
	return ret;
}

static inline intptr_t fd_rbadd_cmp(
	const struct rb_node *n,
	const struct rb_node *ref)
{
	return (intptr_t)rb_entry_of(n, struct file_desc, node)->fd -
		(intptr_t)rb_entry_of(ref, struct file_desc, node)->fd;
}

void fdesc_add(struct fdtab *fdt,
	struct file_desc *d)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&fdt->lock, flags);
	rb_add(&d->node, &fdt->fds, fd_rbadd_cmp);
	spin_unlock_irqrestore(&fdt->lock, flags);
}

static void fdesc_del(struct fdtab *fdt,
	struct file_desc *d)
{
	rb_del(&d->node, &fdt->fds);

	if (d->fd >= 0) {
		__fd_free(fdt, d->fd);
		d->fd = -d->fd;
	}
}

void fdesc_free(struct file_desc *d)
{
	file_free(d->file);
	fd_free(&d->proc->fdt, d->fd);
	kfree(d);
}

static inline intptr_t fd_rbfind_cmp(
	const void *fd, const struct rb_node *ref)
{
	return (intptr_t)fd - rb_entry_of(ref, struct file_desc, node)->fd;
}

static struct file_desc *fdesc_find(
	struct fdtab *fdt, int fd)
{
	return rb_entry(rb_find((void *)(intptr_t)fd,
			fdt->fds, fd_rbfind_cmp), struct file_desc, node);
}

void fdesc_register_atclose(struct file_desc *d,
	struct fdesc_atclose *fdatc)
{
	unsigned long flags = 0;
	struct process *proc = d->proc;
	struct fdtab *fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->atclock, flags);
	list_add_tail(&fdatc->node, &d->atcloses);
	spin_unlock_irqrestore(&fdt->atclock, flags);
}

bool fdesc_unregister_atclose(struct process *proc,
	struct fdesc_atclose *fdatc)
{
	bool ret = false;
	unsigned long flags = 0;
	struct fdtab *fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->atclock, flags);
	ret = !list_empty(&fdatc->node);
	if (ret == true)
		list_del(&fdatc->node);
	spin_unlock_irqrestore(&fdt->atclock, flags);

	return ret;
}

static void fdesc_call_atcloses(struct file_desc *d)
{
	unsigned long flags = 0;
	struct fdesc_atclose *fdatc = NULL;
	struct fdtab *fdt = NULL;

	if (d == NULL)
		return;

	fdt = &d->proc->fdt;

	spin_lock_irqsave(&fdt->atclock, flags);
	while ((fdatc = list_first_entry_or_null(&d->atcloses,
				struct fdesc_atclose, node)) != NULL) {
		list_del(&fdatc->node);
		spin_unlock(&fdt->atclock);
		fdatc->atclose(fdatc);
		spin_lock(&fdt->atclock);
	}
	spin_unlock_irqrestore(&fdt->atclock, flags);
}

struct file_desc *fdesc_get(int fd)
{
	unsigned long flags = 0;
	struct file_desc *d = NULL;
	struct process *proc = current->proc;
	struct fdtab *fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);

	d = fdesc_find(fdt, fd);
	if (d) {
		file_get(d->file);
		d->refc++;
	}

	spin_unlock_irqrestore(&fdt->lock, flags);
	return d;
}

int fdesc_put(struct file_desc *d)
{
	int freed = false;
	unsigned long flags = 0;
	struct file *f = d->file;
	struct fdtab *fdt = &d->proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);

	assert(d->refc > 0);
	if (--d->refc == 0) {
		fdesc_del(fdt, d);
		freed = true;
	}

	spin_unlock_irqrestore(&fdt->lock, flags);

	if (freed) {
		fdesc_call_atcloses(d);
		kfree(d);
	}

	file_put(f);

	return freed;
}

static int fdesc_dup2(struct file *filp, struct file_desc **ppd,
	struct process *proc, int fd)
{
	struct file_desc *d = NULL;

	d = kzalloc(sizeof(struct file_desc));
	if (d == NULL)
		return -ENOMEM;

	d->fd = fd;
	d->file = filp;
	d->proc = proc;
	d->refc = 1;

	file_get(filp);

	fdesc_add(&proc->fdt, d);

	if ((fd == STDOUT_FILENO) && (proc == kproc()))
		printk_setfd(fdesc_get(fd));

	*ppd = d;
	return 0;
}

int fdesc_dup(struct file *filp, struct file_desc **ppd)
{
	int ret = -1, fd = -1;
	struct process *proc = current->proc;
	struct fdtab *fdt = &proc->fdt;

	fd = fd_alloc_lowest(fdt);
	if (fd < 0)
		return fd;

	ret = fdesc_dup2(filp, ppd, proc, fd);
	if (ret != 0)
		fd_free(fdt, fd);

	return ret;
}

int sys_dup(int oldfd)
{
	int ret = -1;
	struct file_desc *oldd = NULL;
	struct file_desc *newd = NULL;

	oldd = fdesc_get(oldfd);
	if (oldd == NULL)
		return -EBADF;

	ret = fdesc_dup(oldd->file, &newd);
	if (ret == 0)
		ret = newd->fd;

	fdesc_put(oldd);
	return ret;
}

int sys_dup2(int oldfd, int newfd)
{
	int ret = 0;
	struct file_desc *oldd = NULL;
	struct file_desc *newd = NULL;
	struct file_desc *d = NULL;
	struct process *proc = current->proc;
	struct fdtab *fdt = &proc->fdt;
	struct file *f = NULL;
	unsigned long flags = 0;

	if ((size_t)newfd >= PROCESS_FD_MAX)
		return -EBADF;

	oldd = fdesc_get(oldfd);
	if (oldd == NULL)
		return -EBADF;

	if (oldfd == newfd) {
		ret = oldfd;
		goto out;
	}

	spin_lock_irqsave(&fdt->lock, flags);

	d = fdesc_find(fdt, newfd);
	if (d != NULL) {
		rb_del(&d->node, &fdt->fds);
		d->fd = -d->fd;
		f = d->file;
		if (--d->refc != 0) /* silently close the conflict filedesc */
			d = NULL;
	} else {
		/* race condition with open() or dup()/dup2() */
		ret = fd_expand_set(fdt, newfd);
	}

	spin_unlock_irqrestore(&fdt->lock, flags);

	if (ret != 0)
		goto out;

	/* silently close the conflict file */
	fdesc_call_atcloses(d);
	kfree(d);
	if (f != NULL)
		file_put(f);

	ret = fdesc_dup2(oldd->file, &newd, proc, newfd);
	if (ret == 0)
		ret = newfd;
	else
		fd_free(fdt, newfd);

out:
	fdesc_put(oldd);
	return ret;
}

static void fd_pool_cleanup(struct fdtab *fdt)
{
	int bmapid = 0, fd = 0;
	struct fd_pool *p = NULL;
	struct file_desc *d = NULL;
	struct file *f = NULL;

	assert(fdt->fds == NULL);
	assert(fdt->depletedpools == NULL);

	if (fdt->pools != NULL) {
		WMSG("remain pools %d\n", fdt->nrpools);
		while ((p = rb_first_entry_postorder(fdt->pools,
					struct fd_pool, node)) != NULL) {
			while ((bmapid = bitmap_next_one(p->bmap, NUMFD_PER_POOL, 0))
						!= NUMFD_PER_POOL) {
				fd = (p->id * NUMFD_PER_POOL) + bmapid;
				WMSG("remain fd %d\n", fd);
				bitmap_clear_bit(p->bmap, bmapid);
				d = fdesc_find(fdt, fd);
				if (d != NULL) {
					f = d->file;
					WMSG("%s%s on %s@%d - fd=%d drefc=%d frefc=%d\n",
						f->fs->mnt.path, f->path,
						d->proc->c->name, d->proc->id, d->fd,
						d->refc, atomic_read(&f->refc));
				}
			}
			fd_pool_free(fdt, p);
		}
	}
}

/*
 * callback for each process cleanup
 * to avoid resource leaking
 */
static void fdesc_cleanup(struct process *proc)
{
	unsigned long flags = 0;
	struct file_desc *d = NULL;
	struct file *f = NULL;
	struct fdtab *fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);

	while ((d = rb_first_entry_postorder(fdt->fds,
				struct file_desc, node)) != NULL) {
		f = d->file;
		LMSG("closing %s%s on %s@%d - fd=%d drefc=%d frefc=%d\n",
			f->fs->mnt.path, f->path,
			d->proc->c->name, d->proc->id, d->fd,
			d->refc, atomic_read(&f->refc));
		spin_unlock(&fdt->lock);
		fdesc_put(d);
		spin_lock(&fdt->lock);
	}

	/* final check */
	fd_pool_cleanup(fdt);

	spin_unlock_irqrestore(&fdt->lock, flags);
}
DECLARE_CLEANUP_LOW(fdesc_cleanup);

int sys_open(const char *path, int fflags, ...)
{
	va_list ap;
	int ret = -1;
	struct file_desc *d = NULL;

	if ((fflags & O_ACCMODE) == (O_WRONLY | O_RDWR))
		return -EINVAL;

	ret = fdesc_alloc(&d, path, fflags);
	if (ret != 0)
		return ret;

	if (d->file->fops->open == NULL) {
		ret = -ENXIO;
		goto out;
	}

	va_start(ap, fflags);
	ret = d->file->fops->open(d->file, va_arg(ap, mode_t), va_arg(ap, void *));
	va_end(ap);
	if (ret != 0) {
		if (ret > 0)
			ret = -ret;
		LMSG("failed open %s %d\n", path, ret);
		goto out;
	}

	ret = d->fd;
	fdesc_add(&d->proc->fdt, d);

	return ret;

out:
	fdesc_free(d);
	return ret;
}

int sys_close(int fd)
{
	struct file *f = NULL;
	struct file_desc *d = NULL;
	unsigned long flags = 0;
	struct process *proc = current->proc;
	struct fdtab *fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);

	d = fdesc_find(fdt, fd);

	if (d == NULL) {
		spin_unlock_irqrestore(&fdt->lock, flags);
		return -EBADF;
	}

	fdesc_del(fdt, d);

	f = d->file;

	assert(d->refc > 0);
	if (--d->refc != 0)
		d = NULL;

	spin_unlock_irqrestore(&fdt->lock, flags);

	fdesc_call_atcloses(d);
	kfree(d);

	file_put(f);

	return 0;
}

ssize_t sys_read(int fd, void *buf, size_t cnt)
{
	ssize_t ret = -EBADF, flags = 0;
	struct file_desc *d = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (d->file->fops->read == NULL) {
		ret = -ENXIO;
		goto out;
	}

	flags = d->file->flags;

	if ((flags & O_DIRECTORY) != 0) {
		ret = -EISDIR;
		goto out;
	}

	if ((flags & O_ACCMODE) == O_WRONLY) {
		ret = -EBADF;
		goto out;
	}

	ret = d->file->fops->read(d->file, buf, cnt);

out:
	fdesc_put(d);
	if (ret < 0)
		LMSG("failed read %ld\n", (long)ret);
	return ret;
}

ssize_t sys_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret = -EBADF, flags = 0;
	struct file_desc *d = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (d->file->fops->write == NULL) {
		ret = -ENXIO;
		goto out;
	}

	flags = d->file->flags;

	if ((flags & O_DIRECTORY) != 0) {
		ret = -EISDIR;
		goto out;
	}

	if ((flags & O_ACCMODE) == O_RDONLY) {
		ret = -EBADF;
		goto out;
	}

	ret = d->file->fops->write(d->file, buf, cnt);

out:
	fdesc_put(d);
	return ret;
}

int sys_ioctl(int fd, int request, unsigned long arg)
{
	int ret = -EBADF;
	struct file_desc *d = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (d->file->fops->ioctl == NULL) {
		ret = -ENXIO;
		goto out;
	}

	if ((d->file->flags & O_DIRECTORY) != 0) {
		ret = -EISDIR;
		goto out;
	}

	ret = d->file->fops->ioctl(d->file, request, arg);

out:
	fdesc_put(d);
	if (ret < 0)
		LMSG("failed ioctl %d\n", ret);
	return ret;
}

off_t sys_lseek(int fd, off_t offset, int whence)
{
	off_t ret = -EBADF;
	struct file_desc *d = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (d->file->fops->lseek == NULL) {
		ret = -ENXIO;
		goto out;
	}

	if ((whence != SEEK_SET) && (whence != SEEK_CUR)
		&& (whence != SEEK_END)) {
		ret = -EINVAL;
		goto out;
	}

	ret = d->file->fops->lseek(d->file, offset, whence);

out:
	fdesc_put(d);
	if (ret < 0)
		LMSG("failed lseek %ld\n", (long)ret);
	return ret;
}

int sys_fstat(int fd, struct stat *st)
{
	int ret = -EBADF;
	struct file_desc *d = NULL;

	if (st == NULL)
		return -EINVAL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (d->file->fops->fstat == NULL) {
		ret = -ENXIO;
		goto out;
	}

	ret = d->file->fops->fstat(d->file, st);

out:
	fdesc_put(d);
	if (ret < 0)
		LMSG("failed fstat %d\n", ret);
	return ret;
}

int sys_ftruncate(int fd, off_t length)
{
	int ret = -EBADF, flags = 0;
	struct file_desc *d = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (d->file->fops->ftruncate == NULL) {
		ret = -ENXIO;
		goto out;
	}

	flags = d->file->flags;

	if ((flags & O_DIRECTORY) != 0) {
		ret = -EISDIR;
		goto out;
	}

	if ((flags & O_ACCMODE) == O_RDONLY) {
		ret = -EINVAL;
		goto out;
	}

	ret = d->file->fops->ftruncate(d->file, length);

out:
	fdesc_put(d);
	if (ret < 0)
		LMSG("failed ftruncate %d\n", ret);
	return ret;
}

int sys_rename(const char *oldpath, const char *newpath)
{
	int ret = -ENOENT;
	struct file_system *fs = NULL;
	struct file_system *nfs = NULL;
	const char *oldp = NULL;
	const char *newp = NULL;

	fs = fs_get(oldpath);
	if (fs == NULL)
		return -ENOENT;

	nfs = fs_get(newpath);
	if (nfs == NULL)
		goto out;

	if (fs->fops->rename == NULL) {
		ret = -ENXIO;
		goto out;
	}

	if (fs != nfs) {
		ret = -EXDEV;
		goto out;
	}

	oldp = fspath_of(fs, oldpath);
	newp = fspath_of(fs, newpath);

	ret = fs->fops->rename(fs, oldp, newp);

out:
	fs_put(fs);
	fs_put(nfs);
	if (ret < 0)
		LMSG("failed rename %s->%s %d\n",
			oldpath, newpath, ret);
	return ret;
}

int sys_unlink(const char *path)
{
	int ret = -1;
	struct file_system *fs = NULL;

	fs = fs_get(path);
	if (fs == NULL)
		return -ENOENT;

	if (fs->fops->unlink == NULL) {
		ret = -ENXIO;
		goto out;
	}

	ret = fs->fops->unlink(fs, fspath_of(fs, path));

out:
	fs_put(fs);
	if (ret < 0)
		LMSG("failed unlink %s %d\n", path, ret);
	return ret;
}

int sys_mkdir(const char *path, mode_t mode)
{
	int ret = -1;
	struct file_system *fs = NULL;

	fs = fs_get(path);
	if (fs == NULL)
		return -ENOENT;

	if (fs->fops->mkdir == NULL) {
		ret = -ENXIO;
		goto out;
	}

	ret = fs->fops->mkdir(fs, fspath_of(fs, path), mode);

out:
	fs_put(fs);
	if (ret < 0)
		LMSG("failed mkdir %s %d\n", path, ret);
	return ret;
}

int sys_rmdir(const char *path)
{
	int ret = -1;
	struct file_system *fs = NULL;

	fs = fs_get(path);
	if (fs == NULL)
		return -ENOENT;

	if (fs->fops->rmdir == NULL) {
		ret = -ENXIO;
		goto out;
	}

	ret = fs->fops->rmdir(fs, fspath_of(fs, path));

out:
	fs_put(fs);
	if (ret < 0)
		LMSG("failed rmdir %s %d\n", path, ret);
	return ret;
}

/*
 * read a single file name in current DIR
 * return the name length in bytes
 */
ssize_t sys_readdir(int fd, struct dirent *e)
{
	int ret = -EBADF;
	struct file_desc *d = NULL;

	if (!e)
		return -EINVAL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (d->file->fops->readdir == NULL) {
		ret = -ENXIO;
		goto out;
	}

	if ((d->file->flags & O_DIRECTORY) == 0) {
		ret = -ENOTDIR;
		goto out;
	}

	e->d_reclen = 0;
	ret = d->file->fops->readdir(d->file, e, sizeof(struct dirent));
	if (ret <= 0)
		goto out;

	/* more one entry from FS? rollback */
	if (ret > e->d_reclen) {
		ret = e->d_reclen;
		d->file->fops->lseek(d->file, e->d_off, SEEK_SET);
	}

out:
	fdesc_put(d);
	return ret;
}

/*
 * read multi-file-names in current DIR
 * return the total length in bytes
 */
ssize_t sys_getdents(int fd, struct dirent *e, size_t count)
{
	ssize_t ret = -EBADF;
	struct file_desc *d = NULL;

	if (!e)
		return -EINVAL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (d->file->fops->readdir == NULL) {
		ret = -ENXIO;
		goto out;
	}

	ret = d->file->fops->readdir(d->file, e, count);

out:
	fdesc_put(d);
	return ret;
}
