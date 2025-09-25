// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * POSIX semaphore implementation (unnamed + named)
 *
 * Named semaphores are exposed via tmpfs/tfs under /sema so that:
 * - access is enforced by tfs_check() (proc->c->ipc_acl)
 * - objects are visible for debugging (ls /sema)
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <file.h>
#include <tfs.h>
#include <init.h>
#include <thread.h>
#include <kmalloc.h>
#include <mutex.h>
#include <spinlock.h>
#include <ksignal.h>
#include <process.h>
#include <semaphore.h>

#define SEM_FS_MOUNT "/sema"

/* Path buffer for "/sema" + "/" + name + NUL */
#define SEM_PATH_MAX (sizeof(SEM_FS_MOUNT) + 1 + SEM_NAME_MAX)

#define SEM_HANDLE_MAGIC 0x53454D48u /* 'SEMH' */

struct sem_obj {
	struct mutex lock;
	struct waitqueue wq;
	unsigned int value;
	unsigned int waiters;
};

struct sem_fnode {
	struct tfs_node node;
	struct sem_obj obj;
};

#define sem_fnode_of(n) container_of(n, struct sem_fnode, node)

struct sem_handle {
	uint32_t magic;
	bool named;
	bool closing;
	int refc; /* external (sem_t) + in-flight ops */
	struct sem_obj *obj;
	struct tfs *fs;
	struct tfs_node *node; /* named: node ref held while external ref exists */
	struct list_head gnode;
};

static LIST_HEAD(sem_handles);
static struct spinlock sem_handles_lock = SPIN_LOCK_INIT(0);

static void sem_handle_put(struct sem_handle *h);
static struct tfs sem_tfs;

static struct sem_handle *sem_handle_lookup(uintptr_t handle)
{
	struct sem_handle *h = NULL;

	list_for_each_entry(h, &sem_handles, gnode) {
		if ((uintptr_t)h == handle)
			return h;
	}

	return NULL;
}

static int sem_handle_get(const sem_t *sem, struct sem_handle **out)
{
	unsigned long flags = 0;
	uintptr_t handle = 0;
	struct sem_handle *h = NULL;
	int perm = 0;

	if (!sem || !out)
		return -EINVAL;

	handle = (uintptr_t)sem->__ksem;
	if (handle == 0)
		return -EINVAL;

	spin_lock_irqsave(&sem_handles_lock, flags);
	h = sem_handle_lookup(handle);
	if (!h || h->magic != SEM_HANDLE_MAGIC || h->closing) {
		spin_unlock_irqrestore(&sem_handles_lock, flags);
		return -EINVAL;
	}
	h->refc++;
	spin_unlock_irqrestore(&sem_handles_lock, flags);

	/* Prevent handle-sharing from bypassing IPC ACL. */
	if (h->named && h->node) {
		perm = tfs_check(h->node);
		if (perm != 0) {
			sem_handle_put(h);
			return perm;
		}
	}

	*out = h;
	return 0;
}

static void sem_handle_put(struct sem_handle *h)
{
	unsigned long flags = 0;
	bool do_free = false;
	struct tfs *fs = NULL;
	struct tfs_node *n = NULL;

	if (!h)
		return;

	spin_lock_irqsave(&sem_handles_lock, flags);
	if (--h->refc == 0) {
		list_del(&h->gnode);
		do_free = true;
		fs = h->fs;
		n = h->node;
	}
	spin_unlock_irqrestore(&sem_handles_lock, flags);

	if (!do_free)
		return;

	if (h->named && fs && n) {
		tfs_lock(fs);
		tfs_put_node(fs, n);
		tfs_unlock(fs);
	} else if (!h->named && h->obj) {
		kfree(h->obj);
	}

	kfree(h);
}

static struct sem_handle *sem_handle_alloc_unnamed(unsigned int value)
{
	unsigned long flags = 0;
	struct sem_handle *h = NULL;
	struct sem_obj *o = NULL;

	h = kzalloc(sizeof(*h));
	o = kzalloc(sizeof(*o));
	if (!h || !o) {
		kfree(h);
		kfree(o);
		return NULL;
	}

	mutex_init(&o->lock);
	waitqueue_init(&o->wq);
	o->value = value;
	o->waiters = 0;

	h->magic = SEM_HANDLE_MAGIC;
	h->named = false;
	h->closing = false;
	h->refc = 1;
	h->obj = o;
	h->fs = NULL;
	h->node = NULL;
	INIT_LIST_HEAD(&h->gnode);

	spin_lock_irqsave(&sem_handles_lock, flags);
	list_add_tail(&h->gnode, &sem_handles);
	spin_unlock_irqrestore(&sem_handles_lock, flags);

	return h;
}

static struct sem_handle *sem_handle_alloc_named(struct tfs *fs, struct tfs_node *n)
{
	unsigned long flags = 0;
	struct sem_handle *h = NULL;

	h = kzalloc(sizeof(*h));
	if (!h)
		return NULL;

	h->magic = SEM_HANDLE_MAGIC;
	h->named = true;
	h->closing = false;
	h->refc = 1;
	h->obj = &sem_fnode_of(n)->obj;
	h->fs = fs;
	h->node = n;
	INIT_LIST_HEAD(&h->gnode);

	spin_lock_irqsave(&sem_handles_lock, flags);
	list_add_tail(&h->gnode, &sem_handles);
	spin_unlock_irqrestore(&sem_handles_lock, flags);

	return h;
}

int sem_init(sem_t *sem, int pshared, unsigned int value)
{
	struct sem_handle *h = NULL;
	uintptr_t handle = 0;
	unsigned long flags = 0;
	struct sem_handle *old = NULL;

	if (!sem)
		return -EINVAL;

	if (pshared)
		return -ENOSYS;

	if (value > SEM_VALUE_MAX)
		return -EINVAL;

	/*
	 * POSIX does not require the caller to zero-initialize sem_t storage.
	 * Only reject if the existing value is a live semaphore handle.
	 */
	handle = (uintptr_t)sem->__ksem;
	if (handle != 0) {
		spin_lock_irqsave(&sem_handles_lock, flags);
		old = sem_handle_lookup(handle);
		if (old && old->magic == SEM_HANDLE_MAGIC && !old->closing) {
			spin_unlock_irqrestore(&sem_handles_lock, flags);
			return -EBUSY;
		}
		spin_unlock_irqrestore(&sem_handles_lock, flags);
		sem->__ksem = 0;
	}

	h = sem_handle_alloc_unnamed(value);
	if (!h)
		return -ENOMEM;

	sem->__ksem = (uintptr_t)h;
	return 0;
}

int sem_destroy(sem_t *sem)
{
	int ret = -1;
	unsigned long flags = 0;
	struct sem_handle *h = NULL;

	ret = sem_handle_get(sem, &h);
	if (ret != 0)
		return ret;

	if (h->named) {
		sem_handle_put(h);
		return -EINVAL;
	}

	mutex_lock(&h->obj->lock);
	if (h->obj->waiters != 0) {
		mutex_unlock(&h->obj->lock);
		sem_handle_put(h);
		return -EBUSY;
	}
	mutex_unlock(&h->obj->lock);

	spin_lock_irqsave(&sem_handles_lock, flags);
	/* strict: other in-flight users still holding refs */
	if (h->refc > 2) {
		spin_unlock_irqrestore(&sem_handles_lock, flags);
		sem_handle_put(h);
		return -EBUSY;
	}
	h->closing = true;
	spin_unlock_irqrestore(&sem_handles_lock, flags);

	sem->__ksem = 0;

	/* drop the external reference */
	sem_handle_put(h);

	/* drop our get reference */
	sem_handle_put(h);
	return 0;
}

int sem_post(sem_t *sem)
{
	int ret = -1;
	struct sem_handle *h = NULL;
	struct sem_obj *o = NULL;

	ret = sem_handle_get(sem, &h);
	if (ret != 0)
		return ret;

	o = h->obj;

	mutex_lock(&o->lock);
	if (o->value == SEM_VALUE_MAX) {
		mutex_unlock(&o->lock);
		sem_handle_put(h);
		return -EOVERFLOW;
	}
	o->value++;
	mutex_unlock(&o->lock);

	wakeup(&o->wq);
	sem_handle_put(h);
	return 0;
}

int sem_wait(sem_t *sem)
{
	int ret = -1;
	long wret = 0;
	struct sem_handle *h = NULL;
	struct sem_obj *o = NULL;

	ret = sem_handle_get(sem, &h);
	if (ret != 0)
		return ret;

	o = h->obj;

	mutex_lock(&o->lock);
	while (o->value == 0) {
		if (is_sigpending(current)) {
			ret = -EINTR;
			goto out;
		}

		o->waiters++;
		wret = wait_event_locked_interruptible(&o->wq,
			o->value > 0, &o->lock);
		if (o->waiters != 0)
			o->waiters--;

		if (wret == -EINTR && o->value == 0) {
			ret = -EINTR;
			goto out;
		}
	}

	o->value--;
	ret = 0;

out:
	mutex_unlock(&o->lock);
	sem_handle_put(h);
	return ret;
}

int sem_trywait(sem_t *sem)
{
	int ret = -1;
	struct sem_handle *h = NULL;
	struct sem_obj *o = NULL;

	ret = sem_handle_get(sem, &h);
	if (ret != 0)
		return ret;

	o = h->obj;

	mutex_lock(&o->lock);
	if (o->value == 0) {
		mutex_unlock(&o->lock);
		sem_handle_put(h);
		return -EAGAIN;
	}
	o->value--;
	mutex_unlock(&o->lock);

	sem_handle_put(h);
	return 0;
}

int sem_timedwait(sem_t *sem, const struct timespec *abstime)
{
	int ret = -1;
	long wret = 0;
	uint64_t timeout = 0;
	struct sem_handle *h = NULL;
	struct sem_obj *o = NULL;

	if (!abstime)
		return -EINVAL;

	ret = abstime2usecs((struct timespec *)abstime, &timeout);
	if (ret != 0)
		return ret;

	ret = sem_handle_get(sem, &h);
	if (ret != 0)
		return ret;

	o = h->obj;

	mutex_lock(&o->lock);
	while (o->value == 0) {
		if (is_sigpending(current)) {
			ret = -EINTR;
			goto out;
		}

		o->waiters++;
		wret = wait_event_timeout_locked_interruptible(&o->wq,
			o->value > 0, timeout, &o->lock);
		if (o->waiters != 0)
			o->waiters--;

		if (wret == -EINTR && o->value == 0) {
			ret = -EINTR;
			goto out;
		}
		if (wret == 0) {
			ret = -ETIMEDOUT;
			goto out;
		}
	}

	o->value--;
	ret = 0;

out:
	mutex_unlock(&o->lock);
	sem_handle_put(h);
	return ret;
}

int sem_getvalue(sem_t *sem, int *sval)
{
	int ret = -1;
	struct sem_handle *h = NULL;
	struct sem_obj *o = NULL;

	if (!sval)
		return -EINVAL;

	ret = sem_handle_get(sem, &h);
	if (ret != 0)
		return ret;

	o = h->obj;

	mutex_lock(&o->lock);
	*sval = o->value;
	mutex_unlock(&o->lock);

	sem_handle_put(h);
	return 0;
}

static int sem_path_of(const char *name, char *out, size_t outsz)
{
	const char *p = name;
	int len = 0;

	if (!name || !out || outsz == 0)
		return -EINVAL;

	/* glibc/Linux convention: syscall passes name without leading '/' */
	if (*p == 0)
		return -EINVAL;
	if (*p == '/' || strchr(p, '/'))
		return -EINVAL;

	len = strlen(p);
	if (len >= SEM_NAME_MAX)
		return -ENAMETOOLONG;

	if (snprintf(out, outsz, "%s/%s", SEM_FS_MOUNT, p) >= outsz)
		return -ENAMETOOLONG;

	return 0;
}

static int sem_open_into(sem_t *sem, const char *name,
	int oflag, mode_t mode, unsigned int value)
{
	int ret = -1;
	struct tfs *fs = &sem_tfs;
	struct tfs_node *n = NULL;
	struct sem_fnode *sn = NULL;
	struct sem_handle *h = NULL;
	char path[SEM_NAME_MAX + 2] = {0};
	int isdir = false;
	int len = 0;

	if (!sem || !name)
		return -EINVAL;
	if (sem->__ksem != 0)
		return -EINVAL;
	if (value > SEM_VALUE_MAX)
		return -EINVAL;

	/*
	 * This path is relative to the mounted /sema filesystem (tfs instance),
	 * so it must NOT include the mount prefix.
	 */
	if (name[0] == 0)
		return -EINVAL;
	if (name[0] == '/' || strchr(name, '/'))
		return -EINVAL;
	len = strlen(name);
	if (len >= SEM_NAME_MAX)
		return -ENAMETOOLONG;
	if (snprintf(path, sizeof(path), "/%s", name) >= sizeof(path))
		return -ENAMETOOLONG;

	tfs_lock(fs);

	n = tfs_get_node(fs, path);
	if (n) {
		ret = tfs_security_check(fs, n);
		if (ret != 0) {
			tfs_put_node(fs, n);
			goto out;
		}

		/* O_EXCL: fail if it already exists */
		if ((oflag & O_CREAT) && (oflag & O_EXCL)) {
			tfs_put_node(fs, n);
			ret = -EEXIST;
			goto out;
		}
	} else {
		if (!(oflag & O_CREAT)) {
			ret = -ENOENT;
			goto out;
		}

		/* refc is 1 after creation */
		ret = tfs_make_node(fs, path, &n, isdir);
		if (ret != 0)
			goto out;

		/* increase refc for open */
		n->refc++;

		sn = sem_fnode_of(n);
		sn->obj.value = value;
		sn->obj.waiters = 0;
	}

	h = sem_handle_alloc_named(fs, n);
	if (!h) {
		if (sn) /* corresponding to creation flow */
			n->refc--;
		tfs_put_node(fs, n);
		ret = -ENOMEM;
		goto out;
	}

	sem->__ksem = (uintptr_t)h;
	ret = 0;

out:
	tfs_unlock(fs);
	return ret;
}

sem_t *sem_open(const char *name, int oflag, ...)
{
	mode_t mode = 0;
	unsigned int value = 0;
	va_list ap;
	sem_t *sem = NULL;
	int ret = -1;

	if (oflag & O_CREAT) {
		va_start(ap, oflag);
		mode = va_arg(ap, mode_t);
		value = va_arg(ap, unsigned int);
		va_end(ap);
	}

	sem = kzalloc(sizeof(*sem));
	if (!sem)
		return ERR_PTR(-ENOMEM);

	ret = sem_open_into(sem, name, oflag, mode, value);
	if (ret != 0) {
		kfree(sem);
		return ERR_PTR(ret);
	}

	return sem;
}

int sem_close(sem_t *sem)
{
	int ret = -1;
	unsigned long flags = 0;
	struct sem_handle *h = NULL;

	ret = sem_handle_get(sem, &h);
	if (ret != 0)
		return ret;

	if (!h->named) {
		sem_handle_put(h);
		return -EINVAL;
	}

	spin_lock_irqsave(&sem_handles_lock, flags);
	h->closing = true;
	spin_unlock_irqrestore(&sem_handles_lock, flags);

	sem->__ksem = 0;

	/* drop external reference */
	sem_handle_put(h);

	/* drop our get reference */
	sem_handle_put(h);
	return 0;
}

int sem_unlink(const char *name)
{
	int ret = -1;
	char path[SEM_PATH_MAX] = {0};

	if (!name)
		return -EINVAL;

	ret = sem_path_of(name, path, sizeof(path));
	if (ret != 0)
		return ret;

	return sys_unlink(path);
}

static struct tfs_node *sem_alloc_node(struct tfs *)
{
	struct sem_fnode *sn = NULL;

	sn = kzalloc(sizeof(*sn));
	if (!sn)
		return NULL;

	mutex_init(&sn->obj.lock);
	waitqueue_init(&sn->obj.wq);
	sn->obj.value = 0;
	sn->obj.waiters = 0;

	return &sn->node;
}

static void sem_free_node(struct tfs_node *n)
{
	struct sem_fnode *sn = sem_fnode_of(n);

	mutex_destroy(&sn->obj.lock);

	kfree(sn);
}

static int sem_open_file(struct file *f, mode_t, void *)
{
	int ret = -1;
	struct tfs *fs = file2tfs(f);
	struct tfs_node *n = NULL;
	int isdir = fspath_isdir(f->path);

	tfs_lock(fs);
	n = tfs_get_node(fs, f->path);
	if (!n) {
		ret = -ENOENT;
		goto out;
	}

	ret = tfs_security_check(fs, n);
	if (ret != 0) {
		tfs_put_node(fs, n);
		goto out;
	}

	tfs_lock_node(n);
	if (n->attr & TFS_ATTR_DIR) {
		if (f->flags & (O_ACCMODE | O_CREAT)) {
			ret = -EISDIR;
			goto outn;
		}

		if (f->flags & (O_TRUNC | O_APPEND)) {
			ret = -EISDIR;
			goto outn;
		}

		f->flags |= O_DIRECTORY;
	} else if (isdir | (f->flags & O_DIRECTORY)) {
		ret = -ENOTDIR;
		goto outn;
	}

	tfs_unlock_node(n);

	f->priv = n;
	ret = 0;
	goto out;

outn:
	tfs_unlock_node(n);
	tfs_put_node(fs, n);

out:
	tfs_unlock(fs);
	return ret;
}

static int sem_close_file(struct file *f)
{
	struct tfs *fs = file2tfs(f);
	struct tfs_node *n = f->priv;

	tfs_lock(fs);
	tfs_put_node(fs, n);
	tfs_unlock(fs);
	return 0;
}

static ssize_t sem_read_file(struct file *f, void *buf, size_t cnt)
{
	struct tfs_node *n = f->priv;
	struct sem_obj *o = &sem_fnode_of(n)->obj;
	char info[128];
	size_t l = 0;

	if (!buf)
		return -EINVAL;
	if (n->attr & TFS_ATTR_DIR)
		return -EISDIR;

	mutex_lock(&o->lock);
	l = snprintf(info, sizeof(info), "value=%u waiters=%u\n",
		o->value, o->waiters);
	mutex_unlock(&o->lock);

	if (l >= cnt)
		return -EMSGSIZE;

	memcpy(buf, info, l + 1);
	return l + 1;
}

static int sem_fstat_file(struct file *f, struct stat *st)
{
	struct tfs_node *n = f->priv;

	if (!st)
		return -EINVAL;

	st->st_size = 0;
	st->st_blksize = PAGE_SIZE;
	st->st_blocks = 0;
	if (n->attr & TFS_ATTR_DIR)
		st->st_mode = S_IFDIR;
	else
		st->st_mode = S_IFREG;
	st->st_atime = n->atime;
	st->st_mtime = n->mtime;
	st->st_ctime = n->ctime;
	return 0;
}

static off_t sem_seekdir(struct file *f, off_t off, int whence)
{
	int ret = -EINVAL;
	struct tfs *fs = file2tfs(f);
	struct tfs_node *n = f->priv;

	tfs_lock(fs);
	ret = tfs_seekdir(fs, n, &f->pos, off, whence);
	tfs_unlock(fs);
	return ret;
}

static ssize_t sem_readdir(struct file *f, struct dirent *d, size_t count)
{
	ssize_t rdbytes = -1;
	struct tfs *fs = file2tfs(f);
	struct tfs_node *n = f->priv;

	if (!d)
		return -EINVAL;

	tfs_lock(fs);
	rdbytes = tfs_readdir(fs, n, &f->pos, d, count);
	tfs_unlock(fs);
	return rdbytes;
}

static int sem_unlink_file(struct file_system *pfs, const char *path)
{
	struct tfs *fs = pfs->priv;
	int ret = -1;

	tfs_lock(fs);
	ret = tfs_unlink(fs, path);
	tfs_unlock(fs);
	return ret;
}

static struct tfs sem_tfs = {
	.alloc = sem_alloc_node,
	.free = sem_free_node,
	.security_check = tfs_check,
};

static const struct file_operations sem_fops = {
	.open = sem_open_file,
	.close = sem_close_file,
	.read = sem_read_file,
	.fstat = sem_fstat_file,
	.unlink = sem_unlink_file,
	.readdir = sem_readdir,
	.lseek = sem_seekdir,
};

static struct file_system sem_fs = {
	.name = "sema",
	.mnt = {SEM_FS_MOUNT, 0, 0},
	.mount = tfs_mount,
	.umount = tfs_umount,
	.getpath = tfs_getpath,
	.putpath = tfs_putpath,
	.fops = &sem_fops,
	.priv = &sem_tfs,
};

static void __init sem_fs_init(void)
{
	assert(fs_mount(&sem_fs) == 0);
}

MODULE_INIT_CORE(sem_fs_init);
