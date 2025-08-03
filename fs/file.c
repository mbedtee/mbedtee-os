// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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
#include <debugfs.h>

#if defined(CONFIG_FILE_DEBUG)
static SPIN_LOCK(__flock);
static LIST_HEAD(__files);
static struct atomic_num nrfiles = ATOMIC_INIT(0);
#endif

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
	if (!p)
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
	if (p) {
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
		if (fdt->nrpools >= PROCESS_FD_MAX / NUMFD_PER_POOL)
			fd = -EMFILE;
		else {
			p = fd_pool_alloc(fdt);
			if (p)
				goto again;
			fd = -ENOMEM;
		}
	}

	spin_unlock_irqrestore(&fdt->lock, flags);

	return fd;
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

	if (fd < 0)
		return -EBADF;

	if (poolid >= fdt->nrpools) {
		/* expand the fd table */
		while (poolid >= fdt->nrpools) {
			p = fd_pool_alloc(fdt);
			if (!p)
				return -ENOMEM;
		}
	} else {
		p = fd_pool_rbfind(&fdt->pools, poolid);
		if (!p)
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

static inline int fd_alloc_lowest(struct fdtab *fdt)
{
	return __fd_alloc(fdt, true);
}

static inline int fd_alloc(struct fdtab *fdt)
{
	return __fd_alloc(fdt, false);
}

static int fd_alloc_from(struct fdtab *fdt, int minfd)
{
	int fd = -1, ret = 0;
	unsigned long flags = 0;

	if (minfd < 0)
		return -EINVAL;

	spin_lock_irqsave(&fdt->lock, flags);
	for (fd = minfd; fd < PROCESS_FD_MAX; fd++) {
		ret = fd_expand_set(fdt, fd);
		if (ret != -EBUSY)
			break;
	}
	if (fd >= PROCESS_FD_MAX)
		fd = -EMFILE;
	else if (ret != 0)
		fd = ret;
	spin_unlock_irqrestore(&fdt->lock, flags);

	return fd;
}

/* lock is held outside */
static void __fd_free(struct fdtab *fdt, int fd)
{
	struct fd_pool *p = NULL;
	int poolid = fd / NUMFD_PER_POOL;
	int bmapid = fd & (NUMFD_PER_POOL - 1);
	struct rb_node **tree = &fdt->pools;

	if (fd < 0)
		return;

	p = fd_pool_rbfind(tree, poolid);
	if (!p) {
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

int file_alloc_pseudo(struct file **ppf,
	const struct file_operations *fops, int fflags)
{
	struct file *f = NULL;

	f = kzalloc(sizeof(*f));
	if (!f)
		return -ENOMEM;

	f->fops = fops;
	f->flags = fflags;
	atomic_set(&f->refc, 1);

#if defined(CONFIG_FILE_DEBUG)
	do {
		unsigned long loflags = 0;

		spin_lock_irqsave(&__flock, loflags);
		atomic_inc(&nrfiles);
		memcpy(f->owner, current->name, sizeof(f->owner));
		list_add_tail(&f->fnode, &__files);
		spin_unlock_irqrestore(&__flock, loflags);
	} while (0);
#endif

	*ppf = f;
	return 0;
}

static int file_alloc(struct file **ppf,
	const char *path, int fflags)
{
	struct file *f = NULL;
	struct file_system *fs = NULL;
	size_t path_len = strlen(path) + 1;

	fs = fs_get(path);
	if (!fs)
		return -ENOENT;

	f = kzalloc(sizeof(*f) + path_len);
	if (!f) {
		fs_put(fs);
		return -ENOMEM;
	}

	f->fs = fs;
	f->fops = fs->fops;
	f->flags = fflags;
	f->path = (char *)(f + 1);
	atomic_set(&f->refc, 1);
	strlcpy(f->path, fspath_of(fs, path), path_len);

#if defined(CONFIG_FILE_DEBUG)
	do {
		unsigned long loflags = 0;

		spin_lock_irqsave(&__flock, loflags);
		atomic_inc(&nrfiles);
		memcpy(f->owner, current->name, sizeof(f->owner));
		list_add_tail(&f->fnode, &__files);
		spin_unlock_irqrestore(&__flock, loflags);
	} while (0);
#endif

	*ppf = f;
	return 0;
}

static void file_free(struct file *f)
{
#if defined(CONFIG_FILE_DEBUG)
	do {
		unsigned long loflags = 0;

		spin_lock_irqsave(&__flock, loflags);
		atomic_dec(&nrfiles);
		list_del(&f->fnode);
		spin_unlock_irqrestore(&__flock, loflags);
	} while (0);
#endif

	fs_put(f->fs);
	kfree(f);
}

void file_put(struct file *f)
{
	if (f && atomic_dec_return(&f->refc) == 0) {
		/*
		 * -- MASK the signal execution --
		 * due to close() may be interrupted by signal
		 */
		thread_enter_critical(current);
		if (f->fops->close)
			f->fops->close(f);
		file_free(f);
		thread_leave_critical(current);
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

static inline intptr_t fd_rbadd_cmp(
	const struct rb_node *n,
	const struct rb_node *ref)
{
	return (intptr_t)rb_entry_of(n, struct file_desc, node)->fd -
		(intptr_t)rb_entry_of(ref, struct file_desc, node)->fd;
}

static inline intptr_t fd_rbfind_cmp(
	const void *fd, const struct rb_node *ref)
{
	return (intptr_t)fd - rb_entry_of(ref, struct file_desc, node)->fd;
}

static struct file_desc *fdesc_find(
	struct fdtab *fdt, int fd)
{
	struct file_desc *d = rb_entry(rb_find((void *)(intptr_t)fd,
			fdt->fds, fd_rbfind_cmp), struct file_desc, node);

	if (d && (d->flags & (FD_CLOSED | FD_OPENING)))
		return NULL;

	return d;
}

/* lock is held outside */
static inline void __fdesc_add(struct fdtab *fdt,
	struct file_desc *d)
{
	rb_add(&d->node, &fdt->fds, fd_rbadd_cmp);
}

static inline void fdesc_add(struct fdtab *fdt,
	struct file_desc *d)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&fdt->lock, flags);
	__fdesc_add(fdt, d);
	spin_unlock_irqrestore(&fdt->lock, flags);
}

/* lock is held outside */
static inline void __fdesc_del(struct fdtab *fdt,
	struct file_desc *d)
{
	rb_del(&d->node, &fdt->fds);
}

void fdesc_free(struct file_desc *d)
{
	unsigned long flags = 0;
	struct fdtab *fdt = &d->proc->fdt;

	file_free(d->file);

	spin_lock_irqsave(&fdt->lock, flags);
	__fdesc_del(fdt, d);
	__fd_free(fdt, d->fd);
	spin_unlock_irqrestore(&fdt->lock, flags);

	kfree(d);
}

static void fdesc_set_cloexec(struct process *proc, int fd)
{
	unsigned long flags = 0;
	struct fdtab *fdt = &proc->fdt;
	struct file_desc *d = NULL;

	spin_lock_irqsave(&fdt->lock, flags);
	d = fdesc_find(fdt, fd);
	if (d)
		d->flags |= FD_CLOEXEC;
	spin_unlock_irqrestore(&fdt->lock, flags);
}

int fdesc_alloc_pseudo(struct file_desc **ppd,
	const struct file_operations *fops, int fflags)
{
	int ret = -1;
	struct file_desc *d = NULL;
	struct file *f = NULL;
	struct process *proc = current->proc;
	struct fdtab *fdt = &proc->fdt;
	int cloexec = 0;
	int oflags = fflags;

	if (oflags & O_CLOEXEC) {
		cloexec = 1;
		oflags &= ~O_CLOEXEC;
	}

	ret = file_alloc_pseudo(&f, fops, oflags);
	if (ret != 0)
		return ret;

	d = kzalloc(sizeof(struct file_desc));
	if (!d) {
		ret = -ENOMEM;
		goto out;
	}

	ret = fd_alloc(fdt);
	if (ret < 0)
		goto out;

	d->fd = ret;
	d->flags = cloexec ? FD_CLOEXEC : 0;
	d->file = f;
	d->proc = proc;
	d->refc = 1;

	d->atcloses = NULL;
	rb_node_init(&d->node);

	d->flags |= FD_OPENING;
	fdesc_add(fdt, d);

	*ppd = d;
	return 0;

out:
	file_free(f);
	kfree(d);
	return ret;
}

int fdesc_alloc(struct file_desc **ppd,
	const char *path, int fflags)
{
	int ret = -1;
	struct file_desc *d = NULL;
	struct file *f = NULL;
	struct process *proc = current->proc;
	struct fdtab *fdt = &proc->fdt;
	int cloexec = 0;
	int oflags = fflags;

	if (oflags & O_CLOEXEC) {
		cloexec = 1;
		oflags &= ~O_CLOEXEC;
	}

	ret = file_alloc(&f, path, oflags);
	if (ret != 0)
		return ret;

	d = kzalloc(sizeof(struct file_desc));
	if (!d) {
		ret = -ENOMEM;
		goto out;
	}

	ret = fd_alloc(fdt);
	if (ret < 0)
		goto out;

	d->fd = ret;
	d->flags = cloexec ? FD_CLOEXEC : 0;
	d->file = f;
	d->proc = proc;
	d->refc = 1;

	d->atcloses = NULL;
	rb_node_init(&d->node);

	d->flags |= FD_OPENING;
	fdesc_add(fdt, d);

	*ppd = d;
	return 0;

out:
	file_free(f);
	kfree(d);
	return ret;
}

void fdesc_register_atclose(struct file_desc *d,
	struct fdesc_atclose *fdatc,
	void (*atclose)(struct fdesc_atclose *fdatc))
{
	unsigned long flags = 0;
	struct process *proc = d->proc;
	struct fdtab *fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->atclock, flags);
	fdatc->atclose = atclose;
	fdatc->owner = d;
	fdatc->next = d->atcloses;
	d->atcloses = fdatc;
	spin_unlock_irqrestore(&fdt->atclock, flags);
}

bool fdesc_unregister_atclose(struct process *proc,
	struct fdesc_atclose *fdatc)
{
	bool ret = false;
	unsigned long flags = 0;
	struct fdtab *fdt = &proc->fdt;
	struct file_desc *d = NULL;
	struct fdesc_atclose **pp = NULL;

	spin_lock_irqsave(&fdt->atclock, flags);
	d = fdatc->owner;
	if (d) {
		pp = &d->atcloses;
		while (*pp) {
			if (*pp == fdatc) {
				*pp = fdatc->next;
				fdatc->next = NULL;
				fdatc->owner = NULL;
				ret = true;
				break;
			}
			pp = &(*pp)->next;
		}
	}
	spin_unlock_irqrestore(&fdt->atclock, flags);

	return ret;
}

static void fdesc_call_atcloses(struct file_desc *d)
{
	unsigned long flags = 0;
	struct fdesc_atclose *fdatc = NULL;
	struct fdtab *fdt = NULL;

	if (!d)
		return;

	fdt = &d->proc->fdt;

	spin_lock_irqsave(&fdt->atclock, flags);
	while ((fdatc = d->atcloses) != NULL) {
		d->atcloses = fdatc->next;
		fdatc->next = NULL;
		fdatc->owner = NULL;
		spin_unlock_irqrestore(&fdt->atclock, flags);
		fdatc->atclose(fdatc);
		spin_lock_irqsave(&fdt->atclock, flags);
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
	struct file *f = NULL;
	struct fdtab *fdt = NULL;

	if (!d)
		return false;

	fdt = &d->proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);

	f = d->file;

	assert(d->refc > 0);
	if (--d->refc == 0) {
		__fdesc_del(fdt, d);
		freed = true;
	}

	spin_unlock_irqrestore(&fdt->lock, flags);

	if (freed) {
		fdesc_call_atcloses(d);
		fd_free(fdt, d->fd);
		kfree(d);
	}

	file_put(f);

	return freed;
}

/* lock is held outside */
static int __fdesc_dup_to_fd(struct file *filp, struct file_desc **ppd,
	struct process *proc, int fd)
{
	struct file_desc *d = NULL;

	d = kzalloc(sizeof(struct file_desc));
	if (!d)
		return -ENOMEM;

	d->fd = fd;
	d->flags = 0;
	d->file = filp;
	d->proc = proc;
	d->refc = 1;
	d->atcloses = NULL;

	file_get(filp);

	__fdesc_add(&proc->fdt, d);

	if ((fd == STDOUT_FILENO) && (proc == kproc()))
		printk_setfd(d);

	*ppd = d;
	return 0;
}

static int fdesc_dup_to_fd(struct file *filp, struct file_desc **ppd,
	struct process *proc, int fd)
{
	int ret = 0;
	unsigned long flags = 0;
	struct fdtab *fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);
	ret = __fdesc_dup_to_fd(filp, ppd, proc, fd);
	spin_unlock_irqrestore(&fdt->lock, flags);

	return ret;
}

int fdesc_dup(struct file *filp, struct file_desc **ppd)
{
	int ret = -1, fd = -1;
	struct process *proc = current->proc;
	struct fdtab *fdt = &proc->fdt;

	fd = fd_alloc_lowest(fdt);
	if (fd < 0)
		return fd;

	ret = fdesc_dup_to_fd(filp, ppd, proc, fd);
	if (ret != 0)
		fd_free(fdt, fd);

	return ret;
}

static int fdesc_dup_min(struct process *proc, struct file *filp,
	int minfd, bool cloexec)
{
	int ret = -1, fd = -1;
	struct file_desc *newd = NULL;
	struct fdtab *fdt = NULL;

	if (!proc || !filp)
		return -EINVAL;

	fdt = &proc->fdt;
	fd = fd_alloc_from(fdt, minfd);
	if (fd < 0)
		return fd;

	ret = fdesc_dup_to_fd(filp, &newd, proc, fd);
	if (ret != 0) {
		fd_free(fdt, fd);
		return ret;
	}

	if (cloexec)
		newd->flags |= FD_CLOEXEC;

	return fd;
}

int fdesc_dup_to(struct process *proc, struct file *filp, int newfd)
{
	int ret = 0;
	struct file_desc *newd = NULL;
	struct file_desc *d = NULL;
	struct fdtab *fdt = NULL;
	unsigned long flags = 0;

	if (!proc || !filp)
		return -EINVAL;

	if ((size_t)newfd >= PROCESS_FD_MAX)
		return -EBADF;

	fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);

	d = fdesc_find(fdt, newfd);
	if (d) {
		/*
		 * Must delete from rbtree BEFORE modifying fd,
		 * otherwise the rbtree ordering is corrupted.
		 * Mark as closed so fdesc_put knows fd is invalid.
		 */
		__fdesc_del(fdt, d);
		d->flags |= FD_CLOSED;
		/* fd marked invalid, don't use -newfd, due to -0 == 0 */
		d->fd = -newfd - 1;
	} else {
		/* reserve the fd slot */
		ret = fd_expand_set(fdt, newfd);
	}

	if (ret == 0) {
		ret = __fdesc_dup_to_fd(filp, &newd, proc, newfd);
		if (ret != 0) {
			if (d) {
				/* restore and re-add to rbtree */
				d->flags &= ~FD_CLOSED;
				d->fd = newfd;
				__fdesc_add(fdt, d);
				d = NULL; /* don't put it */
			} else {
				__fd_free(fdt, newfd);
			}
		} else if (d) {
			/* re-add to rbtree for fdesc_cleanup */
			__fdesc_add(fdt, d);
		}
	}

	spin_unlock_irqrestore(&fdt->lock, flags);

	/* silently close the conflict fdesc */
	fdesc_put(d);

	if (ret != 0)
		return ret;

	return newfd;
}

int fdesc_dup2_to(struct process *proc, int oldfd, int newfd)
{
	int ret = 0;
	struct file_desc *oldd = NULL;
	struct fdtab *fdt = NULL;
	unsigned long flags = 0;

	if (!proc)
		return -EINVAL;
	if ((size_t)oldfd >= PROCESS_FD_MAX)
		return -EBADF;
	if ((size_t)newfd >= PROCESS_FD_MAX)
		return -EBADF;
	if (oldfd == newfd)
		return newfd;

	fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);
	oldd = fdesc_find(fdt, oldfd);
	if (oldd) {
		file_get(oldd->file);
		oldd->refc++;
	}
	spin_unlock_irqrestore(&fdt->lock, flags);

	if (!oldd)
		return -EBADF;

	ret = fdesc_dup_to(proc, oldd->file, newfd);
	fdesc_put(oldd);
	return ret;
}

int fdesc_close_to(struct process *proc, int fd)
{
	struct file_desc *d = NULL;
	struct fdtab *fdt = NULL;
	unsigned long flags = 0;

	if (!proc)
		return -EINVAL;

	fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);

	d = fdesc_find(fdt, fd);
	if (!d) {
		spin_unlock_irqrestore(&fdt->lock, flags);
		return -EBADF;
	}

	/*
	 * Mark as closed instead of removing from rbtree.
	 * fdesc becomes invisible to fdesc_find() but remains
	 * in rbtree for fdesc_cleanup() to reclaim if refc > 1.
	 */
	d->flags |= FD_CLOSED;

	spin_unlock_irqrestore(&fdt->lock, flags);

	fdesc_put(d);

	return 0;
}

int fdesc_close_cloexec(struct process *proc)
{
	int closed = 0;

	if (!proc)
		return -EINVAL;

	while (1) {
		unsigned long flags = 0;
		struct fdtab *fdt = &proc->fdt;
		struct file_desc *d = NULL;
		struct file_desc *n = NULL;
		int fd = -1;

		spin_lock_irqsave(&fdt->lock, flags);
		rb_for_each_entry_safe(d, n, fdt->fds, node) {
			if (d->flags & FD_CLOEXEC) {
				d->refc++;
				file_get(d->file);
				fd = d->fd;
				break;
			}
		}
		spin_unlock_irqrestore(&fdt->lock, flags);

		if (fd < 0)
			break;

		fdesc_close_to(proc, fd);
		fdesc_put(d);
		closed++;
	}

	return closed;
}

int fdesc_open_to(struct process *proc, const char *path,
	int flags, mode_t mode, int fd)
{
	int ret = 0;
	struct file *f = NULL;
	int cloexec = 0;
	int oflags = flags;

	if (!proc || !path)
		return -EINVAL;

	if ((flags & O_ACCMODE) == (O_WRONLY | O_RDWR))
		return -EINVAL;

	if ((size_t)fd >= PROCESS_FD_MAX)
		return -EBADF;

	if (oflags & O_CLOEXEC) {
		cloexec = 1;
		oflags &= ~O_CLOEXEC;
	}

	ret = file_alloc(&f, path, oflags);
	if (ret != 0)
		return ret;

	if (!f->fops->open) {
		file_free(f);
		return -ENXIO;
	}

	ret = f->fops->open(f, mode, NULL);
	if (ret != 0) {
		file_free(f);
		LMSG("failed open %s %d\n", path, ret);
		return ret > 0 ? -ret : ret;
	}

	ret = fdesc_dup_to(proc, f, fd);
	if (ret < 0)
		goto out;

	if (cloexec)
		fdesc_set_cloexec(proc, fd);

	ret = 0;

out:
	/*
	 * Drop the original file_alloc() ref
	 * fdesc_dup_to_fd now owns the reference.
	 */
	file_put(f);
	return ret;
}

int sys_dup(int oldfd)
{
	int ret = -1;
	struct file_desc *oldd = NULL;
	struct file_desc *newd = NULL;

	oldd = fdesc_get(oldfd);
	if (!oldd)
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
	struct process *proc = current->proc;

	if ((size_t)newfd >= PROCESS_FD_MAX)
		return -EBADF;

	oldd = fdesc_get(oldfd);
	if (!oldd)
		return -EBADF;

	if (oldfd == newfd) {
		ret = oldfd;
		goto out;
	}

	ret = fdesc_dup_to(proc, oldd->file, newfd);

out:
	fdesc_put(oldd);
	return ret;
}

int sys_fcntl(int fd, int cmd, unsigned long arg)
{
	int ret = -EBADF;
	struct file_desc *d = NULL;

	d = fdesc_get(fd);
	if (!d)
		return -EBADF;

	switch (cmd) {
	case F_GETFL:
		ret = d->file->flags;
		break;
	case F_SETFL:
		/* Only allow toggling O_NONBLOCK for now */
		d->file->flags = (d->file->flags & ~O_NONBLOCK)
				| (arg & O_NONBLOCK);
		ret = 0;
		break;
	case F_DUPFD:
		ret = fdesc_dup_min(d->proc, d->file, arg, false);
		break;
	case F_DUPFD_CLOEXEC:
		ret = fdesc_dup_min(d->proc, d->file, arg, true);
		break;
	case F_GETFD:
		ret = d->flags;
		break;
	case F_SETFD:
		d->flags = arg & FD_CLOEXEC;
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	fdesc_put(d);
	return ret;
}

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

	if (!d->file->fops->open) {
		ret = -ENXIO;
		goto out;
	}

	va_start(ap, fflags);
	ret = d->file->fops->open(d->file,
		va_arg(ap, mode_t), va_arg(ap, void *));
	va_end(ap);

	if (ret != 0) {
		if (ret > 0)
			ret = -ret;
		LMSG("failed open %s %d\n", path, ret);
		goto out;
	}

	ret = d->fd;
	fdesc_publish(d);

	return ret;

out:
	fdesc_free(d);
	return ret;
}

int sys_close(int fd)
{
	return fdesc_close_to(current->proc, fd);
}

ssize_t sys_read(int fd, void *buf, size_t cnt)
{
	ssize_t ret = -EBADF;
	int flags = 0;
	struct file_desc *d = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (!d->file->fops->read) {
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
	ssize_t ret = -EBADF;
	int flags = 0;
	struct file_desc *d = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (!d->file->fops->write) {
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

	if (!d->file->fops->ioctl) {
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

	if (!d->file->fops->lseek) {
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

ssize_t sys_pread(int fd, void *buf, size_t cnt, off_t offset)
{
	ssize_t ret = -EBADF;
	int flags = 0;
	off_t saved_pos = 0;
	struct file_desc *d = NULL;
	struct file *f = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	f = d->file;

	if (!f->fops->read || !f->fops->lseek) {
		ret = -ENXIO;
		goto out;
	}

	flags = f->flags;

	if ((flags & O_DIRECTORY) != 0) {
		ret = -EISDIR;
		goto out;
	}

	if ((flags & O_ACCMODE) == O_WRONLY) {
		ret = -EBADF;
		goto out;
	}

	saved_pos = f->fops->lseek(f, 0, SEEK_CUR);
	if (saved_pos < 0)
		goto out;
	f->fops->lseek(f, offset, SEEK_SET);
	ret = f->fops->read(f, buf, cnt);
	f->fops->lseek(f, saved_pos, SEEK_SET);

out:
	fdesc_put(d);
	if (ret < 0)
		LMSG("failed pread %ld\n", (long)ret);
	return ret;
}

ssize_t sys_pwrite(int fd, const void *buf, size_t cnt,
	off_t offset)
{
	ssize_t ret = -EBADF;
	int flags = 0;
	off_t saved_pos = 0;
	struct file_desc *d = NULL;
	struct file *f = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	f = d->file;

	if (!f->fops->write || !f->fops->lseek) {
		ret = -ENXIO;
		goto out;
	}

	flags = f->flags;

	if ((flags & O_DIRECTORY) != 0) {
		ret = -EISDIR;
		goto out;
	}

	if ((flags & O_ACCMODE) == O_RDONLY) {
		ret = -EBADF;
		goto out;
	}

	saved_pos = f->fops->lseek(f, 0, SEEK_CUR);
	if (saved_pos < 0)
		goto out;
	f->fops->lseek(f, offset, SEEK_SET);
	ret = f->fops->write(f, buf, cnt);
	f->fops->lseek(f, saved_pos, SEEK_SET);

out:
	fdesc_put(d);
	return ret;
}

int sys_fstat(int fd, struct stat *st)
{
	int ret = -EBADF;
	struct file_desc *d = NULL;

	if (!st)
		return -EINVAL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (!d->file->fops->fstat) {
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

int sys_stat(const char *path, struct stat *st)
{
	int fd = -1, ret = -1;

	if (!path || !st)
		return -EINVAL;

	fd = sys_open(path, O_RDONLY);
	if (fd < 0)
		return fd;

	ret = sys_fstat(fd, st);

	sys_close(fd);

	return ret;
}

int sys_ftruncate(int fd, off_t length)
{
	int ret = -EBADF, flags = 0;
	struct file_desc *d = NULL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (!d->file->fops->ftruncate) {
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
	size_t oldlen = 0;

	fs = fs_get(oldpath);
	if (!fs)
		return -ENOENT;

	nfs = fs_get(newpath);
	if (!nfs)
		goto out;

	if (!fs->fops->rename) {
		ret = -ENXIO;
		goto out;
	}

	if (fs != nfs) {
		ret = -EXDEV;
		goto out;
	}

	oldp = fspath_of(fs, oldpath);
	newp = fspath_of(fs, newpath);

	/* Check if newpath is a subpath of oldpath (or identical) */
	oldlen = strlen(oldp);
	if (strncmp(oldp, newp, oldlen) == 0 &&
	    (newp[oldlen] == '/' || newp[oldlen] == '\0')) {
		ret = -EINVAL;
		goto out;
	}

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
	if (!fs)
		return -ENOENT;

	if (!fs->fops->unlink) {
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
	if (!fs)
		return -ENOENT;

	if (!fs->fops->mkdir) {
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
	if (!fs)
		return -ENOENT;

	if (!fs->fops->rmdir) {
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
 * read multi-files in current DIR
 * return the total length in bytes
 */
ssize_t sys_readdir(int fd, struct dirent *e, size_t count)
{
	ssize_t ret = -EBADF;
	struct file_desc *d = NULL;

	if (!e)
		return -EINVAL;

	d = fdesc_get(fd);
	if (!d)
		return ret;

	if (!d->file->fops->readdir) {
		ret = -ENXIO;
		goto out;
	}

	if ((d->file->flags & O_DIRECTORY) == 0) {
		ret = -ENOTDIR;
		goto out;
	}

	ret = d->file->fops->readdir(d->file, e, count);

out:
	fdesc_put(d);
	return ret;
}

static void fd_pool_cleanup(struct process *proc)
{
	int bmapid = 0, fd = 0;
	struct fd_pool *p = NULL;
	struct file_desc *d = NULL;
	struct file *f = NULL;
	unsigned long flags = 0;
	struct fdtab *fdt = &proc->fdt;

	spin_lock_irqsave(&fdt->lock, flags);

	assert(!fdt->fds);
	assert(!fdt->depletedpools);

	if (fdt->pools) {
		WMSG("oops %04d leaks nrpools %d\n", proc->id, fdt->nrpools);
		while ((p = rb_first_entry_postorder(fdt->pools,
					struct fd_pool, node)) != NULL) {
			while ((bmapid = bitmap_next_one(p->bmap, NUMFD_PER_POOL, 0))
						!= NUMFD_PER_POOL) {
				fd = (p->id * NUMFD_PER_POOL) + bmapid;
				WMSG("oops %04d leaks fd %d\n", proc->id, fd);
				bitmap_clear_bit(p->bmap, bmapid);
				d = fdesc_find(fdt, fd);
				if (d) {
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

	spin_unlock_irqrestore(&fdt->lock, flags);
}

/* Mark each fd FD_CLOSED and release one reference. */
void fdesc_close_all(struct process *proc)
{
	struct fdtab *fdt = &proc->fdt;

	for (;;) {
		struct file_desc *d = NULL;
		unsigned long flags = 0;

		spin_lock_irqsave(&fdt->lock, flags);
		rb_for_each_entry(d, fdt->fds, node) {
			if (!(d->flags & FD_CLOSED)) {
				d->flags |= FD_CLOSED;
				break;
			}
		}
		spin_unlock_irqrestore(&fdt->lock, flags);

		if (!d)
			break;
		fdesc_put(d);
	}
}

static void fdesc_cleanup(struct process *proc)
{
	struct fdtab *fdt = &proc->fdt;
	struct file_desc *d = NULL;

	while ((d = rb_first_entry_postorder(fdt->fds,
				struct file_desc, node)) != NULL)
		fdesc_put(d);

	fd_pool_cleanup(proc);
}
DECLARE_CLEANUP_LOW(fdesc_cleanup);

#if defined(CONFIG_FILE_DEBUG)

static int file_debugfs_read(struct debugfs_file *d)
{
	struct file *f = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&__flock, flags);
	debugfs_printf(d, "\nOpening files: %d\n", atomic_read(&nrfiles));

	list_for_each_entry(f, &__files, fnode) {
		debugfs_printf(d, "%s%s frefc=%d - owner %s\n",
			f->fs ? f->fs->mnt.path : "nil", f->path ? f->path : "nil",
			atomic_read(&f->refc), f->owner);
	}
	spin_unlock_irqrestore(&__flock, flags);

	return 0;
}

static const struct debugfs_fops file_debugfs_ops = {
	.read = file_debugfs_read,
};

static void __init file_debugfs_init(void)
{
	debugfs_create("/files", &file_debugfs_ops);
}
MODULE_INIT(file_debugfs_init);

#endif /* CONFIG_FILE_DEBUG */
