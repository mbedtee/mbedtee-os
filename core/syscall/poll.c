// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * poll() stubs in kernel
 */

#include <file.h>
#include <errno.h>
#include <vmalloc.h>
#include <uaccess.h>

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
	nfds_t nfds; /* user requested number of fds */
	int errcode; /* errno when doing poll wait, e.g. ENOMEM */
	struct pollfd inlinefds[20]; /* in-stack buffer to speed up */

	int wq_condi; /* waitqueue condition meet */
	int inlinenodes_idx; /* current enqueued nodes */
	struct poll_node inlinenodes[20]; /* in-stack buffer to speed up */

	struct poll_table pt;

	struct pollfd *fds;
	struct poll_node_table *nodes;
};

static void poll_wake(struct waitqueue_node *n)
{
	struct thread *t = thread_get(n->id);

	n->wq->condi--;

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

	if (n != NULL)
		return n;

	if (t == NULL || PNODE_FULL(t)) {
		struct poll_node_table *nt = pages_alloc_continuous(PG_RW, 1);

		if (nt == NULL) {
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
	struct thread *__curr = NULL;
	struct poll_node *n = NULL;
	struct poll_queue *pq = container_of(p, struct poll_queue, pt);

	n = poll_get_node(pq);
	if (n == NULL)
		return;

	spin_lock_irqsave(&wq->lock, flags);

	file_get(filp);

	__curr = current;
	__prepare_node(wq, &n->wqn, poll_wake, filp);

	/* just like __prepare_wait() -
	 * __prepare_wait(wq, &n->wqn, false, false);
	 */
	list_add_tail(&n->wqn.node, &wq->list);

	spin_unlock_irqrestore(&wq->lock, flags);
}

/*
 * real wait
 */
static long poll_thread_wait(int msecs)
{
	struct thread *t = current;
	struct waitqueue *waitq = &t->wait_q;

	if (msecs >= 0) {
		uint64_t usecs = (uint64_t)msecs * 1000;

		usecs = wait_timeout(waitq, usecs);

		msecs = usecs / 1000;
	} else {
		wait(waitq);
	}

	return msecs;
}

static int do_poll(struct poll_queue *pq, int timeout)
{
	struct file_desc *d = NULL;
	struct pollfd *pfd = NULL;
	int i = 0, nevents = 0, mask = 0;
	int nfds_inline = ARRAY_SIZE(pq->inlinefds);

	while (1) {
		for (i = 0; i < pq->nfds; i++) {
			pfd = (i < nfds_inline) ? &pq->inlinefds[i] :
					&pq->fds[i - nfds_inline];
			d = fdesc_get(pfd->fd);
			if (d == NULL) {
				pfd->revents = POLLNVAL;
				nevents++;
				continue;
			}

			if (file_can_poll(d->file))
				mask = d->file->fops->poll(d->file, &pq->pt);
			else
				mask = DEFAULT_POLLMASK;

			fdesc_put(d);

			mask &= pfd->events | POLLERR | POLLHUP;

			if (mask) {
				pfd->revents = mask;
				nevents++;
			}
		}

		if (!timeout || nevents)
			break;

		timeout = poll_thread_wait(timeout);
	}

	/* might be failed when alloc nodes */
	if (!nevents)
		nevents = pq->errcode;

	return nevents;
}

static void poll_freewait(struct poll_queue *pq)
{
	int i = 0;
	struct poll_node *n = NULL;
	struct poll_node_table *t = NULL, *nxt = NULL;

	for (i = 0; i < pq->inlinenodes_idx; i++) {
		n = &pq->inlinenodes[i];
		waitqueue_node_del(&n->wqn);
		file_put(n->wqn.priv);
	}

	t = pq->nodes;
	while (t) {
		n = t->node;
		do {
			n--;
			waitqueue_node_del(&n->wqn);
			file_put(n->wqn.priv);
		} while (n > t->nodes);
		nxt = t->next;
		pages_free_continuous(t);
		t = nxt;
	}

	vfree(pq->fds);
}

static int poll_initwait(nfds_t nfds,
	struct pollfd *ufds, struct poll_queue *pq)
{
	int i = 0, ret = -1;
	int nfds_inline = 0, nfds_alloc = 0;

	pq->fds = NULL;
	pq->nodes = NULL;
	pq->nfds = nfds;
	pq->errcode = 0;
	pq->inlinenodes_idx = 0;

	pq->pt.waitfn = poll_waitq_enqueue;

	nfds_inline = min(nfds, (nfds_t)ARRAY_SIZE(pq->inlinefds));

	if (copy_from_user(pq->inlinefds, ufds,
		nfds_inline * sizeof(struct pollfd)))
		return -EFAULT;

	for (i = 0; i < nfds_inline; i++)
		pq->inlinefds[i].revents = 0;

	nfds_alloc = nfds - nfds_inline;

	if (nfds_alloc > 0) {
		pq->fds = vmalloc(nfds_alloc * sizeof(struct pollfd));
		if (pq->fds == NULL)
			return -ENOMEM;

		if (copy_from_user(pq->fds, ufds + nfds_inline,
			nfds_alloc * sizeof(struct pollfd))) {
			ret = -EFAULT;
			goto out;
		}
		for (i = 0; i < nfds_alloc; i++)
			pq->fds[i].revents = 0;
	}

	return 0;

out:
	poll_freewait(pq);
	return ret;
}

long do_syscall_poll(struct pollfd *ufds,
	nfds_t nfds, int timeout)
{
	struct pollfd *pfd = NULL;
	struct poll_queue pq;
	int ret = -1, i = 0, cnt = 0;
	int nfds_inline = ARRAY_SIZE(pq.inlinefds);

	if (!nfds || !ufds)
		return -EINVAL;

	if (nfds >= PROCESS_FD_MAX)
		return -EINVAL;

	ret = poll_initwait(nfds, ufds, &pq);
	if (ret < 0)
		return ret;

	cnt = do_poll(&pq, timeout);

	if (cnt >= 0) {
		for (i = 0; i < nfds; i++) {
			pfd = i < nfds_inline ? &pq.inlinefds[i] : &pq.fds[i - nfds_inline];
			copy_to_user(&ufds[i].revents, &pfd->revents, sizeof(short));
		}
	}

	poll_freewait(&pq);

	return cnt;
}
