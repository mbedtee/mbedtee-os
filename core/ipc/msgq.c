// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * POSIX Message Queue (based on TMPFS)
 */

#include <of.h>
#include <fs.h>
#include <tfs.h>
#include <vma.h>
#include <init.h>
#include <timer.h>
#include <ktime.h>
#include <trace.h>
#include <mqueue.h>
#include <signal.h>
#include <strmisc.h>
#include <uaccess.h>
#include <process.h>
#include <kmalloc.h>
#include <syscall.h>

#include <__pthread.h>
#include <sys/pthread.h>

/* default attributes */
#define MQ_DFT_MSGMAX		(1024)
#define MQ_DFT_MSGSIZEMAX	(65536)

/* Max attributes */
#define MQ_MSGMAX			(32768)
#define MQ_MSGSIZEMAX		(1048576)

static const struct file_operations msgq_fops;

struct msgq_fnode {
	struct tfs_node node;
	struct mq_attr attr;
	struct list_head msgs;
	struct list_head fds;
	struct waitqueue wq_wr;
	struct waitqueue wq_rd;
	struct sigevent evp;
	pthread_attr_t evpattr;
	pid_t evppid;
	bool evpset;
};

#define msgq_fnode_of(n) container_of(n, struct msgq_fnode, node)

struct msg_block {
	struct msg_block *next;
};

struct msg  {
	struct list_head node;
	struct msg_block *blks;
	size_t size;
	unsigned int prio;
};

struct msgq_fd {
	struct list_head node;
	struct file *file;
};

static void msgq_free_msg(struct msg *m);

static int msgq_close(struct file *f)
{
	struct tfs_node *n = f->priv;
	struct tfs *fs = file2tfs(f);

	tfs_lock(fs);
	tfs_put_node(fs, n);
	tfs_unlock(fs);

	return 0;
}

static int msgq_unlink(struct file_system *pfs, const char *path)
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

static struct tfs_node *msgq_alloc_node(struct tfs *fs)
{
	struct msgq_fnode *msgn = kzalloc(sizeof(*msgn));

	if (msgn == NULL)
		return NULL;

	INIT_LIST_HEAD(&msgn->msgs);
	INIT_LIST_HEAD(&msgn->fds);
	waitqueue_init(&msgn->wq_rd);
	waitqueue_init(&msgn->wq_wr);

	return &msgn->node;
}

static void msgq_free_node(struct tfs_node *n)
{
	struct msg *m = NULL, *_m = NULL;
	struct msgq_fd *f = NULL, *_f = NULL;
	struct msgq_fnode *msgn = msgq_fnode_of(n);

	list_for_each_entry_safe(m, _m, &msgn->msgs, node) {
		list_del(&m->node);
		msgq_free_msg(m);
	}

	list_for_each_entry_safe(f, _f, &msgn->fds, node) {
		list_del(&f->node);
		file_put(f->file);
		kfree(f);
	}

	kfree(msgn);
}

static int msgq_do_open(struct tfs *fs,
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

static int msgq_do_create(struct tfs *fs,
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

static int msgq_open(struct file *f,
	mode_t mode, struct mq_attr *attr)
{
	int ret = -1;
	struct msgq_fnode *msgn = NULL;
	struct tfs_node *n = NULL;
	struct tfs *fs = file2tfs(f);
	int isdir = fspath_isdir(f->path);

	if (f->flags & O_CREAT) {
		if (attr && ((attr->mq_maxmsg > MQ_MSGMAX) ||
			(attr->mq_msgsize > MQ_MSGSIZEMAX) ||
			(attr->mq_maxmsg <= 0) ||
			(attr->mq_msgsize <= 0)))
			return -EINVAL;
	}

	tfs_lock(fs);

	n = tfs_get_node(fs, f->path);

	if (n != NULL) {
		ret = msgq_do_open(fs, n, isdir, f);
		if (ret != 0) {
			tfs_put_node(fs, n);
			goto out;
		}
	} else {
		ret = msgq_do_create(fs, &n, isdir, f, mode);
		if (ret != 0)
			goto out;

		msgn = msgq_fnode_of(n);
		if (attr) {
			msgn->attr.mq_maxmsg = attr->mq_maxmsg;
			msgn->attr.mq_msgsize = attr->mq_msgsize;
		} else {
			msgn->attr.mq_maxmsg = MQ_DFT_MSGMAX;
			msgn->attr.mq_msgsize = MQ_DFT_MSGSIZEMAX;
		}
	}

	f->priv = n;
	ret = 0;

out:
	tfs_unlock(fs);
	return ret;
}

mqd_t mq_open(const char *name, int oflag, ...)
{
	int ret = -1;
	va_list ap;

	va_start(ap, oflag);
	ret = sys_open(name, oflag, va_arg(ap, mode_t),
			va_arg(ap, struct mq_attr *));
	va_end(ap);

	return ret;
}

static void evp_notify(struct msgq_fnode *msgn)
{
	int ret = -1;
	struct process *proc = NULL;

	proc = process_get(msgn->evppid);
	if (proc == NULL)
		return;

	if (msgn->evp.sigev_notify == SIGEV_THREAD) {
		ret = pthread_kcreate(proc,
			msgn->evp.sigev_notify_attributes ? &msgn->evpattr : NULL,
			(pthread_func_t)msgn->evp.sigev_notify_function,
			msgn->evp.sigev_value.sival_ptr);
		if (ret > 0)
			sched_ready(ret);
	} else {
		ret = sigenqueue(msgn->evppid, msgn->evp.sigev_signo,
			SI_MESGQ, msgn->evp.sigev_value, false);
	}

	process_put(proc);
}

static void msgq_free_msg(struct msg *m)
{
	struct msg_block *mb = NULL, *next = NULL;

	if (m != NULL) {
		mb = m->blks;
		kfree(m);

		while (mb) {
			next = mb->next;
			kfree(mb);
			mb = next;
		}
	}
}

static struct msg *msgq_alloc_msg(size_t msg_len)
{
	struct msg *m = NULL;
	struct msg_block *mb = NULL, **prev = NULL;
	size_t nrbytes = 0;

	nrbytes = min(msg_len, (size_t)PAGE_SIZE - sizeof(*m));
	m = kmalloc(nrbytes + sizeof(*m));
	if (m == NULL)
		return NULL;

	m->blks = NULL;
	prev = &m->blks;
	msg_len -= nrbytes;

	while (msg_len) {
		nrbytes = min(msg_len, (size_t)PAGE_SIZE - sizeof(*mb));
		mb = kmalloc(nrbytes + sizeof(*mb));
		if (mb == NULL)
			goto out;
		mb->next = NULL;
		*prev = mb;
		prev = &mb->next;
		msg_len -= nrbytes;
	}

	return m;

out:
	msgq_free_msg(m);
	return NULL;
}

static void msgq_write_msg(struct msg *m,
	const char *msg_ptr, size_t msg_len)
{
	size_t nrbytes = 0;
	struct msg_block *mb = NULL;

	nrbytes = min(msg_len, (size_t)PAGE_SIZE - sizeof(*m));
	memcpy(m + 1, msg_ptr, nrbytes);

	mb = m->blks;
	msg_len -= nrbytes;
	msg_ptr += nrbytes;

	while (mb) {
		nrbytes = min(msg_len, (size_t)PAGE_SIZE - sizeof(*mb));
		memcpy(mb + 1, msg_ptr, nrbytes);

		mb = mb->next;
		msg_len -= nrbytes;
		msg_ptr += nrbytes;
	}
}

static void msgq_insert_msg(struct msg *m,
	struct msgq_fnode *msgn)
{
	unsigned int prio = m->prio;
	struct msg *curr = NULL;

	msgn->attr.mq_curmsgs++;

	list_for_each_entry_reverse(curr, &msgn->msgs, node) {
		if (prio <= curr->prio) {
			list_add(&m->node, &curr->node);
			return;
		}
	}

	list_add(&m->node, &msgn->msgs);
}

static int mq_wr_wait(struct msgq_fnode *msgn,
	const struct timespec *abstime)
{
	int ret = 0;
	uint64_t timeout = 0;

	wakeup(&msgn->wq_rd);

	/*
	 * if abstime == NULL, then wait infinitely
	 */
	if (abstime) {
		ret = abstime2usecs(abstime, &timeout);
		if (ret != 0)
			return ret;
		do {
			tfs_unlock_node(&msgn->node);
			timeout = wait_timeout(&msgn->wq_wr, timeout);
			tfs_lock_node(&msgn->node);
		} while ((msgn->attr.mq_curmsgs == msgn->attr.mq_maxmsg) && timeout);

		if (msgn->attr.mq_curmsgs == msgn->attr.mq_maxmsg)
			return -ETIMEDOUT;
	} else {
		do {
			tfs_unlock_node(&msgn->node);
			wait(&msgn->wq_wr);
			tfs_lock_node(&msgn->node);
		} while (msgn->attr.mq_curmsgs == msgn->attr.mq_maxmsg);
	}

	return 0;
}

int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
		unsigned int msg_prio, const struct timespec *abstime)
{
	int ret = -1;
	struct file_desc *d = NULL;
	struct tfs_node *n = NULL;
	struct msgq_fnode *msgn = NULL;
	struct msg *m = NULL;

	if (msg_prio >= MQ_PRIO_MAX)
		return -EINVAL;

	d = fdesc_get(mqdes);
	if (d == NULL)
		return -EBADF;

	if (d->file->fops != &msgq_fops) {
		ret = -EBADF;
		goto outf;
	}

	n = d->file->priv;
	msgn = msgq_fnode_of(n);

	if (msg_len > msgn->attr.mq_msgsize) {
		ret = -EMSGSIZE;
		goto outf;
	}

	m = msgq_alloc_msg(msg_len);
	if (m == NULL) {
		ret = -ENOMEM;
		goto outf;
	}

	m->prio = msg_prio;
	m->size = msg_len;
	msgq_write_msg(m, msg_ptr, msg_len);

	tfs_lock_node(n);

	if (msgn->attr.mq_curmsgs == msgn->attr.mq_maxmsg) {
		if (d->file->flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		} else {
			ret = mq_wr_wait(msgn, abstime);
			if (ret != 0)
				goto out;
		}
	}

	msgq_insert_msg(m, msgn);
	tfs_update_time(NULL, &n->mtime, &n->ctime);
	ret = 0;

	if (msgn->evpset && (msgn->attr.mq_curmsgs == 1) &&
		(list_empty(&msgn->wq_rd.list))) {
		msgn->evpset = false;
		evp_notify(msgn);
	}

out:
	tfs_unlock_node(n);
	wakeup(&msgn->wq_rd);
	if (ret != 0)
		msgq_free_msg(m);
outf:
	fdesc_put(d);
	return ret;
}

static int mq_rd_wait(struct msgq_fnode *msgn,
	const struct timespec *abstime)
{
	int ret = 0;
	uint64_t timeout = 0;

	wakeup(&msgn->wq_wr);

	/*
	 * if abstime == NULL,
	 * then wait infinitely
	 */
	if (abstime) {
		ret = abstime2usecs(abstime, &timeout);
		if (ret != 0)
			return ret;
		do {
			tfs_unlock_node(&msgn->node);
			timeout = wait_timeout(&msgn->wq_rd, timeout);
			tfs_lock_node(&msgn->node);
		} while ((msgn->attr.mq_curmsgs == 0) && timeout);

		if (msgn->attr.mq_curmsgs == 0)
			return -ETIMEDOUT;
	} else {
		do {
			tfs_unlock_node(&msgn->node);
			wait(&msgn->wq_rd);
			tfs_lock_node(&msgn->node);
		} while (msgn->attr.mq_curmsgs == 0);
	}

	return 0;
}

static void msgq_read_msg(struct msg *m,
	char *msg_ptr, size_t msg_len)
{
	size_t nrbytes = 0;
	struct msg_block *mb = NULL;

	nrbytes = min(msg_len, (size_t)PAGE_SIZE - sizeof(*m));
	memcpy(msg_ptr, m + 1, nrbytes);

	mb = m->blks;
	msg_len -= nrbytes;
	msg_ptr += nrbytes;

	while (mb) {
		nrbytes = min(msg_len, (size_t)PAGE_SIZE - sizeof(*mb));
		memcpy(msg_ptr, mb + 1, nrbytes);

		mb = mb->next;
		msg_len -= nrbytes;
		msg_ptr += nrbytes;
	}
}

ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr,
	size_t msg_len, unsigned int *msg_prio,
	const struct timespec *abstime)
{
	ssize_t ret = -1;
	struct file_desc *d = NULL;
	struct tfs_node *n = NULL;
	struct msgq_fnode *msgn = NULL;
	struct msg *m = NULL;

	d = fdesc_get(mqdes);
	if (d == NULL)
		return -EBADF;

	if (d->file->fops != &msgq_fops) {
		ret = -EBADF;
		goto outf;
	}

	n = d->file->priv;
	msgn = msgq_fnode_of(n);

	/* short buffer ? */
	if (msg_len < msgn->attr.mq_msgsize) {
		ret = -EMSGSIZE;
		goto outf;
	}

	tfs_lock_node(n);

	if (msgn->attr.mq_curmsgs == 0) {
		if (d->file->flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		} else {
			ret = mq_rd_wait(msgn, abstime);
			if (ret != 0)
				goto out;
		}
	}

	m = list_first_entry(&msgn->msgs, struct msg, node);

	list_del(&m->node);
	msgn->attr.mq_curmsgs--;
	tfs_update_time(&n->atime, NULL, &n->ctime);
	tfs_unlock_node(n);

	msgq_read_msg(m, msg_ptr, m->size);
	ret = m->size;
	if (msg_prio)
		*msg_prio = m->prio;
	msgq_free_msg(m);
	goto outw;

out:
	tfs_unlock_node(n);
outw:
	wakeup(&msgn->wq_wr);
outf:
	fdesc_put(d);
	return ret;
}

int mq_send(mqd_t mqdes, const char *msg_ptr,
	size_t msg_len, unsigned int msg_prio)
{
	return mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, NULL);
}

int mq_notify(mqd_t mqdes, const struct sigevent *evp)
{
	int ret = -1;
	struct file_desc *d = NULL;
	struct tfs_node *n = NULL;
	struct msgq_fnode *msgn = NULL;
	struct thread *curr = current;

	d = fdesc_get(mqdes);
	if (d == NULL)
		return -EBADF;

	if (d->file->fops != &msgq_fops) {
		ret = -EBADF;
		goto outf;
	}

	n = d->file->priv;
	msgn = msgq_fnode_of(n);

	tfs_lock_node(n);

	if (msgn->evpset && evp) {
		ret = -EBUSY;
		goto out;
	}
	if (!msgn->evpset && !evp) {
		ret = -EINVAL;
		goto out;
	}

	if (evp) {
		memcpy(&msgn->evp, evp, sizeof(msgn->evp));

		if (msgn->evp.sigev_notify == SIGEV_THREAD) {
			if (msgn->evp.sigev_notify_attributes) {
				memcpy(&msgn->evpattr, msgn->evp.sigev_notify_attributes,
					sizeof(msgn->evpattr));

				if (msgn->evpattr.inheritsched == PTHREAD_INHERIT_SCHED) {
					msgn->evpattr.schedpolicy = curr->tuser->policy;
					msgn->evpattr.contentionscope = curr->tuser->scope;
					msgn->evpattr.schedparam.sched_priority = curr->tuser->priority;
				}
			}
		} else if (msgn->evp.sigev_notify == SIGEV_SIGNAL) {
			if (msgn->evp.sigev_signo < 1 || msgn->evp.sigev_signo >= NSIG) {
				ret = -EINVAL;
				goto out;
			}
		} else {
			ret = -EINVAL;
			goto out;
		}
		msgn->evpset = true;
		msgn->evppid = curr->proc->id;
	} else {
		msgn->evpset = false;
	}

	ret = 0;

out:
	tfs_unlock_node(n);
outf:
	fdesc_put(d);
	return ret;
}

int mq_send_fd(mqd_t mqdes, int fd)
{
	int ret = -1;
	struct file *f = NULL;
	struct file_desc *d = NULL, *src = NULL;
	struct tfs_node *n = NULL;
	struct msgq_fnode *msgn = NULL;
	struct msgq_fd *m = NULL;

	d = fdesc_get(mqdes);
	if (d == NULL)
		return -EBADF;

	if (d->file->fops != &msgq_fops) {
		ret = -EBADF;
		goto outf;
	}

	m = kmalloc(sizeof(*m));
	if (m == NULL) {
		ret = -ENOMEM;
		goto outf;
	}

	n = d->file->priv;
	msgn = msgq_fnode_of(n);

	src = fdesc_get(fd);
	if (src == NULL) {
		ret = -EINVAL;
		goto outf;
	}

	f = src->file;

	file_get(f);

	fdesc_put(src);

	tfs_lock_node(n);
	m->file = f;
	list_add_tail(&m->node, &msgn->fds);
	tfs_update_time(NULL, &n->mtime, &n->ctime);
	tfs_unlock_node(n);

	wakeup(&msgn->wq_rd);
	ret = 0;

outf:
	if (ret != 0)
		kfree(m);
	fdesc_put(d);
	return ret;
}

static void mq_waitfd(struct msgq_fnode *msgn)
{
	wakeup(&msgn->wq_wr);

	do {
		tfs_unlock_node(&msgn->node);
		wait(&msgn->wq_rd);
		tfs_lock_node(&msgn->node);
	} while (list_empty(&msgn->fds));
}

static int mq_fd_security_check(struct file *p)
{
	struct process *proc = NULL;

	/* only for device type */
	if (p->dev == NULL)
		return 0;

	proc = current->proc;

	/*
	 * permission permitted
	 */
	if (strstr_delimiter(proc->c->dev_acl, p->path, ','))
		return 0;

	return -EACCES;
}

int mq_receive_fd(mqd_t mqdes, int *pfd)
{
	int ret = -1;
	struct file_desc *d = NULL, *dst = NULL;
	struct tfs_node *n = NULL;
	struct msgq_fnode *msgn = NULL;
	struct msgq_fd *m = NULL;

	d = fdesc_get(mqdes);
	if (d == NULL)
		return -EBADF;

	if (d->file->fops != &msgq_fops) {
		ret = -EBADF;
		goto outf;
	}

	n = d->file->priv;
	msgn = msgq_fnode_of(n);

	tfs_lock_node(n);

	if (list_empty(&msgn->fds)) {
		if (d->file->flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		} else {
			mq_waitfd(msgn);
		}
	}

	m = list_first_entry(&msgn->fds, struct msgq_fd, node);

	ret = mq_fd_security_check(m->file);
	if (ret != 0)
		goto out;

	ret = fdesc_dup(m->file, &dst);
	if (ret != 0)
		goto out;

	list_del(&m->node);
	file_put(m->file);
	kfree(m);
	tfs_update_time(&n->atime, NULL, &n->ctime);

	*pfd = dst->fd;
	ret = 0;

out:
	tfs_unlock_node(n);
outf:
	fdesc_put(d);
	return ret;
}

int mq_setattr(mqd_t mqdes, const struct mq_attr *mqstat,
	struct mq_attr *omqstat)
{
	struct file_desc *d = NULL;
	struct tfs_node *n = NULL;
	struct msgq_fnode *msgn = NULL;

	if (mqstat && (mqstat->mq_flags & (~O_NONBLOCK)))
		return -EINVAL;

	d = fdesc_get(mqdes);
	if (d == NULL)
		return -EBADF;

	if (d->file->fops != &msgq_fops) {
		fdesc_put(d);
		return -EBADF;
	}

	n = d->file->priv;
	msgn = msgq_fnode_of(n);

	if (omqstat) {
		memcpy(omqstat, &msgn->attr, sizeof(*omqstat));
		omqstat->mq_flags = d->file->flags & O_NONBLOCK;
	}

	if (mqstat) {
		tfs_lock_node(n);

		if (mqstat->mq_flags & O_NONBLOCK)
			d->file->flags |= O_NONBLOCK;
		else
			d->file->flags &= ~O_NONBLOCK;

		tfs_update_time(&n->atime, NULL,
			&n->ctime);

		tfs_unlock_node(n);
	}

	fdesc_put(d);
	return 0;
}

int mq_getattr(mqd_t mqdes, struct mq_attr *mqstat)
{
	return mq_setattr(mqdes, NULL, mqstat);
}

static ssize_t msgq_read(struct file *f, void *buf, size_t cnt)
{
	size_t l = 0;
	struct tfs_node *n = f->priv;
	struct msgq_fnode *msgn = msgq_fnode_of(n);
	char info[128];

	if (buf == NULL)
		return -EINVAL;

	tfs_lock_node(n);

	l = snprintf(info, sizeof(info), "MaxMsgs: %ld MaxMsgSize: %ld CurMsgs: %ld\n",
		msgn->attr.mq_maxmsg, msgn->attr.mq_msgsize, msgn->attr.mq_curmsgs);

	tfs_update_time(&n->atime, NULL, NULL);

	tfs_unlock_node(n);

	if (l >= cnt)
		return -EMSGSIZE;

	strlcpy(buf, info, l);

	return l + 1;
}

static int msgq_fstat(struct file *f, struct stat *st)
{
	struct tfs_node *n = f->priv;
	struct msgq_fnode *msgn = msgq_fnode_of(n);

	if (st == NULL)
		return -EINVAL;

	tfs_lock_node(n);

	st->st_size = msgn->attr.mq_curmsgs;
	st->st_blksize = PAGE_SIZE;
	st->st_blocks = 0;

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

static off_t msgq_seekdir(struct file *f, off_t off, int whence)
{
	int ret = -EINVAL;
	struct tfs *fs = file2tfs(f);
	struct tfs_node *n = f->priv;

	tfs_lock(fs);

	ret = tfs_seekdir(fs, n, &f->pos, off, whence);

	tfs_unlock(fs);
	return ret;
}

static ssize_t msgq_readdir(struct file *f, struct dirent *d, size_t count)
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

static const struct file_operations msgq_fops = {
	.open = (void *)msgq_open,
	.close = msgq_close,
	.read = msgq_read,

	.fstat = msgq_fstat,
	.unlink = msgq_unlink,
	.readdir = msgq_readdir,
	.lseek = msgq_seekdir
};

static struct tfs msgq_tfs = {
	.alloc = msgq_alloc_node,
	.free = msgq_free_node,
	.security_check = tfs_check
};

static struct file_system msgq_fs = {
	/* based on the tmpfs */
	.name = "msgfs",
	.mnt = {"/msgq", 0, 0},
	.mount = tfs_mount,
	.umount = tfs_umount,
	.getpath = tfs_getpath,
	.putpath = tfs_putpath,
	.fops = &msgq_fops,

	/* independent tmpfs instance */
	.priv = &msgq_tfs,
};

static void __init msgq_init(void)
{
	assert(fs_mount(&msgq_fs) == 0);
}

MODULE_INIT_CORE(msgq_init);
