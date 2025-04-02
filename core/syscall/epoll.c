// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * epoll interface
 */

#include <file.h>
#include <errno.h>
#include <kmalloc.h>
#include <uaccess.h>
#include <init.h>
#include <sys/poll.h>

#include <tfs.h>
#include <epoll.h>

#define DEFAULT_EPOLLMASK (EPOLLIN | EPOLLOUT | EPOLLRDNORM | EPOLLWRNORM)

static const struct file_operations epoll_fops;

struct epoll_fnode {
	struct tfs_node node;
	struct list_head rdlist;
	struct waitqueue wq;
	struct rb_node *fds;
	int refc;
	struct spinlock lock;
};

struct epoll_item {
	/* node @ fds */
	struct rb_node node;
	/* node @ rdlist */
	struct list_head rdnode;
	/*
	 * wait queue nodes' list on this item
	 * queued by - epoll_waitq_enqueue()
 	 * protected by epoll_item->lock
	 */
	struct list_head wqnlist;
	/* @ which epoll file */
	struct epoll_fnode *epfn;
	struct epoll_event event;
	struct file_desc *fdesc;
	/* cleanup callback called @ fdesc close */
	struct fdesc_atclose fdatc;

	struct spinlock lock;
};

struct epoll_queue {
	struct poll_table pt;
	struct epoll_item *ei;
	int errcode;
};

struct epoll_queue_node {
	struct waitqueue_node wqn;
	/* node @ wqnlist */
	struct list_head node;
};

#define epoll_fnode_of(n) container_of(n, struct epoll_fnode, node)

static inline intptr_t epi_rbfind_cmp(
	const void *fdesc, const struct rb_node *ref)
{
	struct file_desc *dst = (void *)fdesc;
	struct epoll_item *ei = rb_entry_of(ref, struct epoll_item, node);
	struct file_desc *refd = ei->fdesc;

	return dst < refd ? -1 :
		   dst > refd ? + 1 : 0;
}

static inline intptr_t epi_rbadd_cmp(
	const struct rb_node *n, const struct rb_node *ref)
{
	struct epoll_item *ei = rb_entry_of(n, struct epoll_item, node);
	struct epoll_item *ei_ref = rb_entry_of(n, struct epoll_item, node);

	return ei->fdesc < ei_ref->fdesc ? -1 :
		   ei->fdesc > ei_ref->fdesc ? + 1 : 0;
}

static inline struct epoll_item *epoll_find(
	struct epoll_fnode *epfn, struct file_desc *dst)
{
	return rb_entry(rb_find((void *)dst, epfn->fds,
		epi_rbfind_cmp), struct epoll_item, node);
}

static inline void epoll_rbadd(
	struct epoll_fnode *epfn, struct epoll_item *ei)
{
	rb_add(&ei->node, &epfn->fds, epi_rbadd_cmp);
}

static int epoll_item_poll(struct epoll_item *ei,
	struct poll_table *pt)
{
	int mask = 0;
	struct file *f = ei->fdesc->file;

	if (!f->fops->poll)
		mask = DEFAULT_EPOLLMASK;
	else
		mask = f->fops->poll(f, pt);

	mask &= ei->event.events | EPOLLERR | EPOLLHUP;

	return mask;
}

static void epoll_wake(struct waitqueue_node *n)
{
	struct epoll_item *ei = n->priv;
	struct epoll_fnode *epfn = ei->epfn;
	unsigned long flags = 0;

	n->wq->condi--;

	spin_lock_irqsave(&epfn->lock, flags);

	if (ei->event.events & ~EPOLLHIGHMASK) {
		if (list_empty(&ei->rdnode))
			list_add_tail(&ei->rdnode, &epfn->rdlist);

		wakeup(&epfn->wq);
	}

	spin_unlock_irqrestore(&epfn->lock, flags);
}

static void epoll_waitq_enqueue(struct file *filp,
	struct waitqueue *wq, struct poll_table *p)
{
	unsigned long flags = 0;
	struct thread *__curr = NULL;
	struct epoll_queue *epq = container_of(p, struct epoll_queue, pt);
	struct epoll_item *ei = epq->ei;
	struct epoll_queue_node *eqn = NULL;

	eqn = kmalloc(sizeof(*eqn));
	if (eqn == NULL) {
		epq->errcode = -ENOMEM;
		return;
	}

	/* assert(filp == ei->fdesc->file); */

	spin_lock_irqsave(&wq->lock, flags);

	__curr = current;

	__prepare_node(wq, &eqn->wqn, epoll_wake, ei);

	/*
	 * just like __prepare_wait() -
	 * __prepare_wait(wq, &en->wqn, false, false);
	 */
	list_add_tail(&eqn->wqn.node, &wq->list);

	spin_unlock_irqrestore(&wq->lock, flags);

	spin_lock_irqsave(&ei->lock, flags);
	list_add_tail(&eqn->node, &ei->wqnlist);
	spin_unlock_irqrestore(&ei->lock, flags);
}

static void epoll_waitq_dequeue(struct epoll_item *ei)
{
	unsigned long flags = 0;
	struct epoll_queue_node *n = NULL, *_n = NULL;

	spin_lock_irqsave(&ei->lock, flags);

	list_for_each_entry_safe(n, _n, &ei->wqnlist, node) {
		list_del(&n->node);
		waitqueue_node_del(&n->wqn);
		kfree(n);
	}

	spin_unlock_irqrestore(&ei->lock, flags);
}

static void epoll_rditem_dequeue(struct epoll_fnode *epfn,
	struct epoll_item *ei)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&epfn->lock, flags);
	list_del(&ei->rdnode);
	spin_unlock_irqrestore(&epfn->lock, flags);
}

static void epoll_rditem_enqueue(struct epoll_fnode *epfn,
	struct epoll_item *ei)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&epfn->lock, flags);
	if (list_empty(&ei->rdnode)) {
		list_add_tail(&ei->rdnode, &epfn->rdlist);
		wakeup(&epfn->wq);
	}
	spin_unlock_irqrestore(&epfn->lock, flags);
}

static void __epoll_del(struct epoll_fnode *epfn,
	struct epoll_item *ei)
{
	epoll_waitq_dequeue(ei);

	epoll_rditem_dequeue(epfn, ei);

	rb_del(&ei->node, &epfn->fds);

	--epfn->refc;

	assert(epfn->refc >= 0);
	kfree(ei);
}

static int epoll_del(struct epoll_fnode *epfn,
	struct epoll_item *ei)
{
	if (fdesc_unregister_atclose(ei->fdesc, &ei->fdatc))
		__epoll_del(epfn, ei);
	else
		rb_del(&ei->node, &epfn->fds);

	return 0;
}

static void epoll_fdatc(struct fdesc_atclose *p)
{
	bool to_free = false;
	struct epoll_item *ei = container_of(p, struct epoll_item, fdatc);
	struct epoll_fnode *epfn = ei->epfn;

	tfs_lock_node(&epfn->node);

	__epoll_del(epfn, ei);

	to_free = (epfn->refc == 0);

	tfs_unlock_node(&epfn->node);

	if (to_free) {
		wakeup(&epfn->wq);
		waitqueue_flush(&epfn->wq);
		kfree(epfn);
	}
}

static int epoll_add(struct epoll_fnode *epfn,
	struct file_desc *dst, struct epoll_event *evt)
{
	struct epoll_item *ei = NULL;
	struct epoll_queue epq;
	int revents = 0;

	if (evt == NULL)
		return -EINVAL;

	ei = kmalloc(sizeof(*ei));
	if (ei == NULL)
		return -ENOMEM;

	ei->event = *evt;
	ei->fdesc = dst;
	ei->epfn = epfn;
	INIT_LIST_HEAD(&ei->rdnode);
	INIT_LIST_HEAD(&ei->wqnlist);
	rb_node_init(&ei->node);
	spin_lock_init(&ei->lock);

	INIT_LIST_HEAD(&ei->fdatc.node);
	ei->fdatc.atclose = epoll_fdatc;

	epoll_rbadd(epfn, ei);
	epfn->refc++;

	epq.ei = ei;
	epq.errcode = 0;
	epq.pt.waitfn = epoll_waitq_enqueue;
	revents = epoll_item_poll(ei, &epq.pt);

	if (epq.errcode) {
		__epoll_del(epfn, ei);
		return epq.errcode;
	}

	if (revents)
		epoll_rditem_enqueue(epfn, ei);

	fdesc_register_atclose(dst, &ei->fdatc);

	return 0;
}

static int epoll_modify(struct epoll_fnode *epfn,
	struct epoll_item *ei, const struct epoll_event *evt)
{
	struct poll_table pt = {NULL};

	if (evt == NULL)
		return -EINVAL;

	ei->event = *evt;

	if (epoll_item_poll(ei, &pt))
		epoll_rditem_enqueue(epfn, ei);

	return 0;
}

int epoll_create(int size)
{
	int ret = -1;
	char path[64];

	if (size < 0)
		return -EINVAL;

	do {
		if (!sprintf(path, "/epoll/%04d_%08d", current_id, rand()))
			return -EFAULT;
		ret = sys_open(path, O_RDWR | O_CREAT | O_EXCL);
	} while (ret == -EEXIST);

	return ret;
}

int epoll_ctl(int epfd, int op, int fd,
	struct epoll_event *event)
{
	int ret = -1;
	struct tfs_node *n = NULL;
	struct epoll_fnode *epfn = NULL;
	struct epoll_item *ei = NULL;
	struct file_desc *epd = NULL, *dst = NULL;

	epd = fdesc_get(epfd);
	if (epd == NULL)
		return -EBADF;

	if (epd->file->fops != &epoll_fops) {
		ret = -EINVAL;
		goto outf;
	}

	/* get the target file descriptor */
	dst = fdesc_get(fd);
	if (dst == NULL) {
		ret = -EBADF;
		goto outf;
	}

	if (dst->file->fops == &epoll_fops) {
		ret = -EINVAL;
		goto outf2;
	}

	n = epd->file->priv;
	epfn = epoll_fnode_of(n);

	tfs_lock_node(n);

	ei = epoll_find(epfn, dst);

	switch (op) {
	case EPOLL_CTL_ADD:
		ret = !ei ? epoll_add(epfn, dst, event) : -EEXIST;
		break;
	case EPOLL_CTL_DEL:
		ret = ei ? epoll_del(epfn, ei) : -ENOENT;
		break;
	case EPOLL_CTL_MOD:
		ret = ei ? epoll_modify(epfn, ei, event) : -ENOENT;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	tfs_unlock_node(n);

outf2:
	fdesc_put(dst);
outf:
	fdesc_put(epd);
	return ret;
}

static int epoll_xfer_events(struct epoll_fnode *epfn,
	struct epoll_event *events, int maxevents)
{
	uint32_t revents = 0, nrevents = 0;
	struct poll_table pt = {NULL};
	unsigned long flags = 0;
	struct epoll_item *ei = NULL, *_ei = NULL;

	spin_lock_irqsave(&epfn->lock, flags);

	list_for_each_entry_safe(ei, _ei, &epfn->rdlist, rdnode) {
		if (nrevents >= maxevents)
			break;

		list_del(&ei->rdnode);

		revents = epoll_item_poll(ei, &pt);
		if (!revents)
			continue;

		if (put_user(revents, &events[nrevents].events) ||
			put_user(ei->event.data, &events[nrevents].data)) {
			list_add(&ei->rdnode, &epfn->rdlist);
			if (!nrevents)
				nrevents = -EFAULT;
			break;
		}

		if (ei->event.events & EPOLLONESHOT)
			ei->event.events &= EPOLLHIGHMASK;
		else if (!(ei->event.events & EPOLLET))
			list_add_tail(&ei->rdnode, &epfn->rdlist);

		nrevents++;
	}

	spin_unlock_irqrestore(&epfn->lock, flags);

	return nrevents;
}

int epoll_wait(int epfd, struct epoll_event *events,
		       int maxevents, int timemsecs)
{
	int ret = -1;
	struct file_desc *epd = NULL;
	struct tfs_node *n = NULL;
	struct epoll_fnode *epfn = NULL;
	uint64_t timeusecs = (uint64_t)timemsecs * 1000;

	if (maxevents <= 0 || maxevents > EPOLL_MAXEVENTS)
		return -EINVAL;

	epd = fdesc_get(epfd);
	if (epd == NULL)
		return -EBADF;

	if (epd->file->fops != &epoll_fops) {
		ret = -EINVAL;
		goto outf;
	}

	n = epd->file->priv;
	epfn = epoll_fnode_of(n);

	while (1) {
		ret = epoll_xfer_events(epfn, events, maxevents);
		if (ret)
			break;

		if (timeusecs == 0) {
			ret = 0;
			break;
		}

		if (is_sigpending(current)) {
			ret = -EINTR;
			break;
		}

		timeusecs = wait_event_timeout_interruptible(&epfn->wq,
				!list_empty(&epfn->rdlist), timeusecs);

		if (timemsecs == -1)
			timeusecs = INT_MAX;
	}

outf:
	fdesc_put(epd);
	return ret;
}

static struct tfs_node *epoll_alloc_node(struct tfs *fs)
{
	struct epoll_fnode *epfn = kzalloc(sizeof(*epfn));

	if (epfn == NULL)
		return NULL;

	epfn->refc = 1;
	epfn->fds = NULL;
	INIT_LIST_HEAD(&epfn->rdlist);
	waitqueue_init(&epfn->wq);
	spin_lock_init(&epfn->lock);

	return &epfn->node;
}

static void epoll_free_node(struct tfs_node *n)
{
	struct epoll_item *ei = NULL;
	struct epoll_fnode *epfn = epoll_fnode_of(n);
	bool to_free = false;

	tfs_lock_node(&epfn->node);

	while ((ei = rb_first_entry_postorder(epfn->fds,
				struct epoll_item, node)) != NULL)
		epoll_del(epfn, ei);

	to_free = (--epfn->refc == 0);

	tfs_unlock_node(&epfn->node);

	wakeup(&epfn->wq);

	if (to_free) {
		waitqueue_flush(&epfn->wq);
		kfree(epfn);
	}
}

static int epoll_do_open(struct tfs *fs,
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

static int epoll_do_create(struct tfs *fs,
	struct tfs_node **n, int isdir,
	struct file *f, mode_t mode)
{
	int ret = -1;
	int flags = f->flags;

	if (!(flags & O_CREAT))
		return -ENOENT;

	if (isdir)
		return -EISDIR;

	if (flags & O_DIRECTORY)
		return -ENOTDIR;

	ret = tfs_make_node(fs, f->path, n, false);
	if (ret != 0)
		return ret;

	(*n)->refc++;

	return ret;
}

static int epoll_open(struct file *f,
	mode_t mode, void *arg)
{
	int ret = -1;
	struct tfs_node *n = NULL;
	struct tfs *fs = file2tfs(f);
	int isdir = fspath_isdir(f->path);

	tfs_lock(fs);

	n = tfs_get_node(fs, f->path);

	if (n != NULL) {
		ret = epoll_do_open(fs, n, isdir, f);
		if (ret != 0) {
			tfs_put_node(fs, n);
			goto out;
		}
	} else {
		ret = epoll_do_create(fs, &n, isdir, f, mode);
		if (ret != 0)
			goto out;
	}

	f->priv = n;
	ret = 0;

out:
	tfs_unlock(fs);
	return ret;
}

static int epoll_close(struct file *f)
{
	struct tfs_node *n = f->priv;
	struct tfs *fs = file2tfs(f);

	tfs_lock(fs);
	tfs_put_node(fs, n); /* close */
	tfs_put_node(fs, n); /* unlink */
	tfs_unlock(fs);

	return 0;
}

static int epoll_unlink(struct file_system *pfs, const char *path)
{
	int ret = -1;
	struct tfs_node *n = NULL;
	struct tfs *fs = pfs->priv;

	if (!path)
		return -EINVAL;

	tfs_lock(fs);

	n = tfs_get_node(fs, path);
	if (n == NULL) {
		ret = -ENOENT;
		goto out;
	}

	if (n->attr & TFS_ATTR_DIR) {
		ret = -EISDIR;
		goto out;
	}

	if (fspath_isdir(path)) {
		ret = -ENOTDIR;
		goto out;
	}

	ret = tfs_security_check(fs, n);
	if (ret != 0)
		goto out;

	list_del(&n->node);

	tfs_put_node(fs, n);

out:
	tfs_put_node(fs, n);
	tfs_unlock(fs);
	return ret;
}

static int epoll_fstat(struct file *f, struct stat *st)
{
	struct tfs_node *n = f->priv;
	struct epoll_fnode *epfn = epoll_fnode_of(n);

	if (st == NULL)
		return -EINVAL;

	tfs_lock_node(n);

	st->st_size = epfn->refc;
	st->st_blksize = 1;
	st->st_blocks = !list_empty(&epfn->rdlist);

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

static off_t epoll_seekdir(struct file *f, off_t off, int whence)
{
	int ret = -EINVAL;
	struct tfs *fs = file2tfs(f);
	struct tfs_node *n = f->priv;

	tfs_lock(fs);

	ret = tfs_seekdir(fs, n, &f->pos, off, whence);

	tfs_unlock(fs);
	return ret;
}

static ssize_t epoll_readdir(struct file *f, struct dirent *d, size_t count)
{
	ssize_t rdbytes = -1;
	struct tfs *fs = file2tfs(f);
	struct tfs_node *n = f->priv;

	if (d == NULL)
		return -EINVAL;

	tfs_lock(fs);

	rdbytes = tfs_readdir(fs, n, &f->pos, d, count);

	tfs_unlock(fs);
	return rdbytes;
}

static const struct file_operations epoll_fops = {
	.open = epoll_open,
	.close = epoll_close,
	.poll = NULL,
	.lseek = epoll_seekdir,
	.readdir = epoll_readdir,
	.fstat = epoll_fstat,
	.unlink = epoll_unlink
};

/* based on the tmpfs */
static struct tfs epoll_tfs = {
	.alloc = epoll_alloc_node,
	.free = epoll_free_node,
	.security_check = tfs_check,
};

static struct file_system epoll_fs = {
	/* based on the tmpfs */
	.name = "ep-fs",
	.mnt = {"/epoll", 0, 0},
	.mount = tfs_mount,
	.umount = tfs_umount,
	.getpath = tfs_getpath,
	.putpath = tfs_putpath,

	.fops = &epoll_fops,

	/* independent tmpfs instance */
	.priv = &epoll_tfs,
};

static void __init epoll_fs_init(void)
{
	assert(fs_mount(&epoll_fs) == 0);
}

MODULE_INIT_LATE(epoll_fs_init);
