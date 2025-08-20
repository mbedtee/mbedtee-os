// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * poll() stubs in kernel
 */

#include <file.h>
#include <errno.h>
#include <vmalloc.h>
#include <uaccess.h>
#include <sleep.h>
#include <limits.h>

#include <sys/poll.h>

#define DEFAULT_POLLMASK (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM)

#define PNODE_FULL(t) ((unsigned long)((t)->node + 1) > \
		(unsigned long)(t) + PAGE_SIZE)

struct poll_node {
	struct waitqueue_node wqn;
};

struct poll_node_table {
	struct poll_node_table *next;
	struct poll_node *node;
	struct poll_node nodes[];
};

struct poll_queue {
	struct list_head node; /* node in thread's polls list */

	nfds_t nfds; /* user requested number of fds */
	int errcode; /* errno when doing poll wait, e.g. ENOMEM */

	struct pollfd inlinefds[5]; /* in-stack buffer to speed up */
	struct poll_node inlinenodes[5]; /* in-stack buffer to speed up */
	int inlinenodes_idx; /* current enqueued nodes */

	struct poll_table pt;

	struct pollfd *fds;
	struct poll_node_table *nodes;
};

static void poll_wake(struct waitqueue_node *n)
{
	struct thread *t = thread_get(n->id);

	if (t)
		wakeup(&t->wait_q);

	thread_put(t);
}

static struct poll_node *poll_get_inlinenode(struct poll_queue *pq)
{
	struct poll_node *n = NULL;

	if (ARRAY_SIZE(pq->inlinenodes) > pq->inlinenodes_idx) {
		n = &pq->inlinenodes[pq->inlinenodes_idx++];
		/* waitqueue_node_init(&n->wqn); */
	}

	return n;
}

static struct poll_node *poll_get_node(struct poll_queue *pq)
{
	struct poll_node *n = poll_get_inlinenode(pq);
	struct poll_node_table *t = pq->nodes;

	if (n)
		return n;

	if (!t || PNODE_FULL(t)) {
		struct poll_node_table *nt = pages_alloc_continuous(PG_RW, 1);

		if (!nt) {
			pq->errcode = -ENOMEM;
			return NULL;
		}
		nt->node = nt->nodes;
		nt->next = t;
		pq->nodes = nt;

		t = nt;
	}

	return t->node++;
}

static void poll_waitq_enqueue(struct file *filp,
	struct waitqueue *wq, struct poll_table *p)
{
	unsigned long flags = 0;
	struct poll_node *n = NULL;
	struct poll_queue *pq = container_of(p, struct poll_queue, pt);

	n = poll_get_node(pq);
	if (!n)
		return;

	spin_lock_irqsave(&wq->lock, flags);

	file_get(filp);

	waitqueue_node_enqueue(wq, &n->wqn, poll_wake, filp);

	spin_unlock_irqrestore(&wq->lock, flags);
}

/*
 * real wait - interruptible so that signals can break poll()
 */
static long poll_thread_wait(int msecs)
{
	long wret = 0;
	struct thread *t = current;
	struct waitqueue *waitq = &t->wait_q;

	if (msecs >= 0) {
		uint64_t usecs = (uint64_t)msecs * 1000;

		wret = wait_timeout_interruptible(waitq, usecs);
		if (wret == -EINTR)
			return -EINTR;

		msecs = wret / 1000;
	} else {
		if (wait_interruptible(waitq) == -EINTR)
			return -EINTR;
	}

	return msecs;
}

static int do_poll(struct poll_queue *pq, int timemsecs)
{
	struct file_desc *d = NULL;
	struct pollfd *pfd = NULL;
	int i = 0, nevents = 0, mask = 0;
	int nfds_inline = ARRAY_SIZE(pq->inlinefds);
	struct poll_table *pt = &pq->pt;

	while (1) {
		for (i = 0; i < pq->nfds; i++) {
			pfd = (i < nfds_inline) ? &pq->inlinefds[i] :
					&pq->fds[i - nfds_inline];
			d = fdesc_get(pfd->fd);
			if (!d) {
				pfd->revents = POLLNVAL;
				nevents++;
				continue;
			}

			if (file_can_poll(d->file))
				mask = d->file->fops->poll(d->file, pt);
			else
				mask = DEFAULT_POLLMASK;

			fdesc_put(d);

			mask &= pfd->events | POLLERR | POLLHUP;

			if (mask != 0) {
				pfd->revents = mask;
				nevents++;
				/* found one, then other waiters are unnecessary */
				pt->waitfn = NULL;
			}
		}

		if (timemsecs == 0 || nevents != 0)
			break;

		timemsecs = poll_thread_wait(timemsecs);
		if (timemsecs == -EINTR)
			return -EINTR;
	}

	/* might be failed when alloc nodes */
	if (nevents == 0)
		nevents = pq->errcode;

	return nevents;
}

static void poll_freewait(struct poll_queue *pq)
{
	int i = 0;
	struct poll_node *n = NULL;
	struct poll_node_table *t = NULL, *nxt = NULL;

	list_del(&pq->node);

	for (i = 0; i < pq->inlinenodes_idx; i++) {
		n = &pq->inlinenodes[i];
		waitqueue_node_del_release(&n->wqn);
		file_put(n->wqn.priv);
	}

	t = pq->nodes;
	while (t) {
		n = t->node;
		do {
			n--;
			waitqueue_node_del_release(&n->wqn);
			file_put(n->wqn.priv);
		} while (n > t->nodes);
		nxt = t->next;
		pages_free_continuous(t);
		t = nxt;
	}

	vfree(pq->fds);
}

static int poll_initwait(nfds_t nfds, struct pollfd *fds,
	struct poll_queue *pq, bool iskerncall)
{
	int i = 0, ret = -1;
	int nfds_inline = 0, nfds_alloc = 0;

	pq->fds = NULL;
	pq->nodes = NULL;
	pq->nfds = nfds;
	pq->errcode = 0;
	pq->inlinenodes_idx = 0;
	INIT_LIST_HEAD(&pq->node);
	pq->pt.waitfn = poll_waitq_enqueue;

	nfds_inline = min(nfds, (nfds_t)ARRAY_SIZE(pq->inlinefds));

	if (!iskerncall) {
		if (copy_from_user(pq->inlinefds, fds,
			nfds_inline * sizeof(struct pollfd)))
			return -EFAULT;
	} else {
		memcpy(pq->inlinefds, fds,
			nfds_inline * sizeof(struct pollfd));
	}

	for (i = 0; i < nfds_inline; i++)
		pq->inlinefds[i].revents = 0;

	nfds_alloc = nfds - nfds_inline;

	if (nfds_alloc > 0) {
		pq->fds = vmalloc(nfds_alloc * sizeof(struct pollfd));
		if (!pq->fds)
			return -ENOMEM;

		if (!iskerncall) {
			if (copy_from_user(pq->fds, fds + nfds_inline,
				nfds_alloc * sizeof(struct pollfd))) {
				ret = -EFAULT;
				goto out;
			}
		} else {
			memcpy(pq->fds, fds + nfds_inline,
				nfds_alloc * sizeof(struct pollfd));
		}

		for (i = 0; i < nfds_alloc; i++)
			pq->fds[i].revents = 0;
	}

	/*
	 * link to thread's poll list to be cleaned up
	 * if the thread is killed (e.g. by SIGKILL)
	 */
	list_add_tail(&pq->node, &current->polls);
	return 0;

out:
	poll_freewait(pq);
	return ret;
}

/*
 * called from user space
 *
 * timemsecs:
 *    > 0 : wait timeout msecs
 *    = 0 : no blocking
 *    < 0 : infinite blocking
 */
long do_syscall_poll(struct pollfd *ufds, nfds_t nfds, int timemsecs)
{
	struct pollfd *pfd = NULL;
	struct poll_queue pq;
	int ret = -1, i = 0, cnt = 0;
	int nfds_inline = ARRAY_SIZE(pq.inlinefds);

	if (nfds == 0) {
		msleep_interruptible(timemsecs);
		return 0;
	}

	if (!ufds)
		return -EINVAL;

	if (nfds >= PROCESS_FD_MAX)
		return -EINVAL;

	ret = poll_initwait(nfds, ufds, &pq, false);
	if (ret < 0)
		return ret;

	cnt = do_poll(&pq, timemsecs);

	if (cnt >= 0) {
		for (i = 0; i < nfds; i++) {
			pfd = i < nfds_inline ? &pq.inlinefds[i] : &pq.fds[i - nfds_inline];
			copy_to_user(&ufds[i].revents, &pfd->revents, sizeof(short));
		}
	}

	poll_freewait(&pq);

	return cnt;
}

/*
 * called from kernel space
 *
 * timemsecs:
 *    > 0 : wait timeout msecs
 *    = 0 : no blocking
 *    < 0 : infinite blocking
 */
int poll(struct pollfd *fds, nfds_t nfds, int timemsecs)
{
	struct pollfd *pfd = NULL;
	struct poll_queue pq;
	int ret = -1, i = 0, cnt = 0;
	int nfds_inline = ARRAY_SIZE(pq.inlinefds);

	if (nfds == 0) {
		msleep_interruptible(timemsecs);
		return 0;
	}

	if (!fds)
		return -EINVAL;

	if (nfds >= PROCESS_FD_MAX)
		return -EINVAL;

	ret = poll_initwait(nfds, fds, &pq, true);
	if (ret < 0)
		return ret;

	cnt = do_poll(&pq, timemsecs);

	if (cnt >= 0) {
		for (i = 0; i < nfds; i++) {
			pfd = i < nfds_inline ? &pq.inlinefds[i] : &pq.fds[i - nfds_inline];
			memcpy(&fds[i].revents, &pfd->revents, sizeof(short));
		}
	}

	poll_freewait(&pq);

	return cnt;
}

static void poll_cleanup_t(struct thread *t)
{
	struct poll_queue *pq = NULL, *n = NULL;

	list_for_each_entry_safe(pq, n, &t->polls, node)
		poll_freewait(pq);
}
DECLARE_THREAD_CLEANUP_HIGH(poll_cleanup_t);
