// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * POSIX pipe implementation
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <file.h>
#include <fcntl.h>
#include <mutex.h>
#include <thread.h>
#include <kmalloc.h>
#include <sys/poll.h>
#include <sys/stat.h>

#include <ksignal.h>

/* Minimum POSIX atomic write size requirement is 512 bytes. */
#define PIPE_ATOMIC_MAX 512

/* Keep the buffer modest; enough for typical small IO and tests. */
#define PIPE_CAPACITY (4096)

struct pipe_core {
	struct mutex lock;
	struct waitqueue wq_rd;
	struct waitqueue wq_wr;

	size_t rd;
	size_t wr;
	bool full;

	unsigned int readers;
	unsigned int writers;

	unsigned char *buf;
};

struct pipe_end {
	struct pipe_core *pc;
	bool is_read;
};

static inline size_t pipe_used(const struct pipe_core *pc)
{
	if (pc->full)
		return PIPE_CAPACITY;
	if (pc->wr >= pc->rd)
		return pc->wr - pc->rd;
	return PIPE_CAPACITY + pc->wr - pc->rd;
}

static inline size_t pipe_free(const struct pipe_core *pc)
{
	return PIPE_CAPACITY - pipe_used(pc);
}

static size_t pipe_read_locked(struct pipe_core *pc, void *dst, size_t cnt)
{
	size_t n = cnt;
	size_t remain = 0;
	size_t used = pipe_used(pc);
	size_t rd = pc->rd;

	if (n > used)
		n = used;

	if (rd + n > PIPE_CAPACITY) {
		remain = rd + n - PIPE_CAPACITY;
		memcpy(dst, &pc->buf[rd], n - remain);
		memcpy((uint8_t *)dst + (n - remain), &pc->buf[0], remain);
		rd = remain;
	} else {
		memcpy(dst, &pc->buf[rd], n);
		rd += n;
		if (rd == PIPE_CAPACITY)
			rd = 0;
	}

	pc->rd = rd;
	if (n != 0)
		pc->full = false;

	return n;
}

static size_t pipe_write_locked(struct pipe_core *pc, const void *src, size_t cnt)
{
	size_t n = cnt;
	size_t remain = 0;
	size_t wr = pc->wr;

	if (n > pipe_free(pc))
		n = pipe_free(pc);

	if (wr + n > PIPE_CAPACITY) {
		remain = wr + n - PIPE_CAPACITY;
		memcpy(&pc->buf[wr], src, n - remain);
		memcpy(&pc->buf[0], (const uint8_t *)src + (n - remain), remain);
		wr = remain;
	} else {
		memcpy(&pc->buf[wr], src, n);
		wr += n;
		if (wr == PIPE_CAPACITY)
			wr = 0;
	}

	pc->wr = wr;
	if (n != 0 && pc->wr == pc->rd)
		pc->full = true;

	return n;
}

static ssize_t pipe_read(struct file *filp, void *buf, size_t cnt)
{
	ssize_t ret = -EINVAL;
	struct pipe_end *pe = filp->priv;
	struct pipe_core *pc = NULL;

	if (!pe || !pe->is_read)
		return -EBADF;
	if (!buf)
		return -EINVAL;
	if (cnt == 0)
		return 0;

	pc = pe->pc;

	mutex_lock(&pc->lock);
	while (pipe_used(pc) == 0) {
		/* EOF if no writers remain */
		if (pc->writers == 0) {
			ret = 0;
			goto out;
		}

		if (filp->flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}

		if (wait_event_locked_interruptible(&pc->wq_rd,
			(pipe_used(pc) > 0) || (pc->writers == 0),
			&pc->lock) == -EINTR) {
			ret = -EINTR;
			goto out;
		}
	}

	ret = pipe_read_locked(pc, buf, cnt);
	if (ret > 0)
		wakeup(&pc->wq_wr);

out:
	mutex_unlock(&pc->lock);
	return ret;
}

static ssize_t pipe_write(struct file *filp, const void *buf, size_t cnt)
{
	ssize_t ret = -EINVAL;
	size_t written = 0;
	struct pipe_end *pe = filp->priv;
	struct pipe_core *pc = NULL;

	if (!pe || pe->is_read)
		return -EBADF;
	if (!buf)
		return -EINVAL;
	if (cnt == 0)
		return 0;

	pc = pe->pc;

	mutex_lock(&pc->lock);

	if (pc->readers == 0) {
		ret = -EPIPE;
		goto out;
	}

	/* For small writes (<= PIPE_ATOMIC_MAX), keep the write atomic. */
	if (cnt <= PIPE_ATOMIC_MAX) {
		while (pipe_free(pc) < cnt) {
			if (pc->readers == 0) {
				ret = -EPIPE;
				goto out;
			}
			if (filp->flags & O_NONBLOCK) {
				ret = -EAGAIN;
				goto out;
			}

			if (wait_event_locked_interruptible(&pc->wq_wr,
				(pipe_free(pc) >= cnt) || (pc->readers == 0),
				&pc->lock) == -EINTR) {
				ret = -EINTR;
				goto out;
			}
		}

		pipe_write_locked(pc, buf, cnt);
		written = cnt;
	} else {
		while (written < cnt) {
			while (pipe_free(pc) == 0) {
				if (pc->readers == 0) {
					ret = written != 0 ? written : -EPIPE;
					goto out;
				}
				if (filp->flags & O_NONBLOCK) {
					ret = written != 0 ? written : -EAGAIN;
					goto out;
				}

				if (written != 0)
					wakeup(&pc->wq_rd);

				if (wait_event_locked_interruptible(&pc->wq_wr,
					(pipe_free(pc) > 0) || (pc->readers == 0),
					&pc->lock) == -EINTR) {
					ret = written != 0 ? written : -EINTR;
					goto out;
				}
			}

			written += pipe_write_locked(pc, (const uint8_t *)buf + written,
				cnt - written);
		}
	}

	ret = written;

out:
	if (written != 0)
		wakeup(&pc->wq_rd);
	mutex_unlock(&pc->lock);
	return ret;
}

static int pipe_close(struct file *filp)
{
	struct pipe_end *pe = filp->priv;
	struct pipe_core *pc = NULL;
	bool do_free = false;

	if (!pe)
		return 0;

	pc = pe->pc;

	mutex_lock(&pc->lock);
	if (pe->is_read) {
		if (pc->readers != 0)
			pc->readers--;
	} else {
		if (pc->writers != 0)
			pc->writers--;
	}

	/* Wake peers so they can observe EOF/EPIPE. */
	wakeup(&pc->wq_rd);
	wakeup(&pc->wq_wr);

	do_free = (pc->readers == 0) && (pc->writers == 0);
	mutex_unlock(&pc->lock);

	kfree(pe);
	filp->priv = NULL;

	if (do_free) {
		kfree(pc->buf);
		kfree(pc);
	}

	return 0;
}

static int pipe_poll(struct file *filp, struct poll_table *pt)
{
	int mask = 0;
	struct pipe_end *pe = filp->priv;
	struct pipe_core *pc = NULL;

	if (!pe)
		return POLLERR;

	pc = pe->pc;

	/* Register wait queues for poll/epoll. */
	poll_wait(filp, &pc->wq_rd, pt);
	poll_wait(filp, &pc->wq_wr, pt);

	mutex_lock(&pc->lock);
	if (pe->is_read) {
		if (pipe_used(pc) != 0)
			mask |= POLLIN | POLLRDNORM;
		if (pc->writers == 0)
			mask |= POLLHUP | POLLIN | POLLRDNORM;
	} else {
		if (pc->readers == 0)
			mask |= POLLERR;
		if (pipe_free(pc) != 0)
			mask |= POLLOUT | POLLWRNORM;
	}
	mutex_unlock(&pc->lock);

	return mask;
}

static off_t pipe_lseek(struct file *, off_t, int)
{
	return -ESPIPE;
}

static int pipe_fstat(struct file *filp, struct stat *st)
{
	struct pipe_end *pe = filp->priv;
	struct pipe_core *pc = NULL;
	unsigned int used = 0;

	if (!st)
		return -EINVAL;

	if (!pe)
		return -EBADF;

	pc = pe->pc;
	mutex_lock(&pc->lock);
	used = pipe_used(pc);
	mutex_unlock(&pc->lock);

	st->st_mode = S_IFIFO;
	st->st_size = used;
	st->st_blksize = PIPE_CAPACITY;
	st->st_blocks = (used + PIPE_CAPACITY - 1) / PIPE_CAPACITY;
	st->st_atime = 0;
	st->st_mtime = 0;
	st->st_ctime = 0;

	return 0;
}

static const struct file_operations pipe_fops = {
	.close = pipe_close,
	.read = pipe_read,
	.write = pipe_write,
	.poll = pipe_poll,
	.lseek = pipe_lseek,
	.fstat = pipe_fstat,
};

int sys_pipe2(int pipefd[2], int flags)
{
	int ret = -1;
	struct pipe_core *pc = NULL;
	struct pipe_end *rd_end = NULL;
	struct pipe_end *wr_end = NULL;
	struct file_desc *rd_desc = NULL;
	struct file_desc *wr_desc = NULL;
	const int allowed = O_NONBLOCK | O_CLOEXEC;
	int fflags = 0;

	if (!pipefd)
		return -EFAULT;

	if (flags & ~allowed)
		return -EINVAL;

	if (flags & O_NONBLOCK)
		fflags |= O_NONBLOCK;
	if (flags & O_CLOEXEC)
		fflags |= O_CLOEXEC;

	pc = kzalloc(sizeof(*pc));
	if (!pc)
		return -ENOMEM;

	pc->buf = kzalloc(PIPE_CAPACITY);
	if (!pc->buf) {
		kfree(pc);
		return -ENOMEM;
	}

	mutex_init(&pc->lock);
	waitqueue_init(&pc->wq_rd);
	waitqueue_init(&pc->wq_wr);

	rd_end = kzalloc(sizeof(*rd_end));
	wr_end = kzalloc(sizeof(*wr_end));
	if (!rd_end || !wr_end) {
		ret = -ENOMEM;
		goto out;
	}

	rd_end->pc = pc;
	rd_end->is_read = true;
	wr_end->pc = pc;
	wr_end->is_read = false;

	ret = fdesc_alloc_pseudo(&rd_desc, &pipe_fops, O_RDONLY | fflags);
	if (ret != 0)
		goto out;
	rd_desc->file->priv = rd_end;
	pc->readers++;

	ret = fdesc_alloc_pseudo(&wr_desc, &pipe_fops, O_WRONLY | fflags);
	if (ret != 0)
		goto out;
	wr_desc->file->priv = wr_end;
	pc->writers++;

	fdesc_publish(rd_desc);
	fdesc_publish(wr_desc);

	pipefd[0] = rd_desc->fd;
	pipefd[1] = wr_desc->fd;
	return 0;

out:
	if (rd_desc)
		fdesc_free(rd_desc);

	if (wr_desc)
		fdesc_free(wr_desc);

	kfree(rd_end);
	kfree(wr_end);
	kfree(pc->buf);
	kfree(pc);

	return ret;
}

int sys_pipe(int pipefd[2])
{
	return sys_pipe2(pipefd, 0);
}
