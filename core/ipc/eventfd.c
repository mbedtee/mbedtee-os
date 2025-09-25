// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * eventfd implementation (pollable counter-based event source)
 *
 * Semantics (Linux-like):
 * - counter is uint64_t, max is UINT64_MAX-1
 * - read() returns 8 bytes:
 *     - normal mode: returns counter and resets it to 0
 *     - semaphore mode: returns 1 and decrements counter by 1
 * - write() takes 8 bytes (non-zero) and adds to counter (blocks/EAGAIN on overflow)
 * - poll() supports POLLIN when counter>0 and POLLOUT when counter not at max
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <eventfd.h>

#include <file.h>
#include <kmalloc.h>
#include <ksignal.h>
#include <mutex.h>
#include <thread.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <wait.h>

#define EVENTFD_COUNTER_MAX (UINT64_MAX - 1ULL)

struct eventfd_core {
	struct mutex lock;
	struct waitqueue wq;
	uint64_t counter;
	bool semaphore;
};

static ssize_t eventfd_file_read(struct file *filp, void *buf, size_t cnt)
{
	struct eventfd_core *ec = filp->priv;
	uint64_t val = 0;

	if (!ec)
		return -EBADF;
	if (!buf)
		return -EINVAL;
	if (cnt < sizeof(val))
		return -EINVAL;

	mutex_lock(&ec->lock);
	while (ec->counter == 0) {
		if (filp->flags & O_NONBLOCK) {
			mutex_unlock(&ec->lock);
			return -EAGAIN;
		}

		if (wait_event_locked_interruptible(&ec->wq, ec->counter > 0,
				&ec->lock) == -EINTR && ec->counter == 0) {
			mutex_unlock(&ec->lock);
			return -EINTR;
		}
	}

	if (ec->semaphore) {
		val = 1;
		ec->counter--;
	} else {
		val = ec->counter;
		ec->counter = 0;
	}

	wakeup(&ec->wq);
	mutex_unlock(&ec->lock);

	memcpy(buf, &val, sizeof(val));
	return sizeof(val);
}

static ssize_t eventfd_file_write(struct file *filp, const void *buf, size_t cnt)
{
	struct eventfd_core *ec = filp->priv;
	uint64_t val = 0;

	if (!ec)
		return -EBADF;
	if (!buf)
		return -EINVAL;
	if (cnt < sizeof(val))
		return -EINVAL;

	memcpy(&val, buf, sizeof(val));
	if (val == 0)
		return -EINVAL;

	mutex_lock(&ec->lock);
	while (ec->counter > EVENTFD_COUNTER_MAX - val) {
		if (filp->flags & O_NONBLOCK) {
			mutex_unlock(&ec->lock);
			return -EAGAIN;
		}

		if (wait_event_locked_interruptible(&ec->wq,
			ec->counter <= EVENTFD_COUNTER_MAX - val,
			&ec->lock) == -EINTR && ec->counter > EVENTFD_COUNTER_MAX - val) {
			mutex_unlock(&ec->lock);
			return -EINTR;
		}
	}

	ec->counter += val;
	wakeup(&ec->wq);
	mutex_unlock(&ec->lock);

	return sizeof(val);
}

static int eventfd_poll(struct file *filp, struct poll_table *pt)
{
	int mask = 0;
	struct eventfd_core *ec = filp->priv;

	if (!ec)
		return POLLERR;

	poll_wait(filp, &ec->wq, pt);

	mutex_lock(&ec->lock);
	if (ec->counter > 0)
		mask |= POLLIN | POLLRDNORM;
	if (ec->counter < EVENTFD_COUNTER_MAX)
		mask |= POLLOUT | POLLWRNORM;
	mutex_unlock(&ec->lock);

	return mask;
}

static off_t eventfd_lseek(struct file *, off_t, int)
{
	return -ESPIPE;
}

static int eventfd_fstat(struct file *filp, struct stat *st)
{
	struct eventfd_core *ec = filp->priv;
	uint64_t used = 0;

	if (!st)
		return -EINVAL;
	if (!ec)
		return -EBADF;

	mutex_lock(&ec->lock);
	used = ec->counter;
	mutex_unlock(&ec->lock);

	st->st_mode = S_IFIFO;
	st->st_size = used;
	st->st_blksize = 0;
	st->st_blocks = 0;
	st->st_atime = 0;
	st->st_mtime = 0;
	st->st_ctime = 0;

	return 0;
}

static int eventfd_close(struct file *filp)
{
	struct eventfd_core *ec = filp->priv;

	if (!ec)
		return 0;

	/* Best-effort wake any sleepers before teardown. */
	wakeup(&ec->wq);
	waitqueue_flush(&ec->wq);

	filp->priv = NULL;
	kfree(ec);
	return 0;
}

static const struct file_operations eventfd_fops = {
	.close = eventfd_close,
	.read = eventfd_file_read,
	.write = eventfd_file_write,
	.poll = eventfd_poll,
	.lseek = eventfd_lseek,
	.fstat = eventfd_fstat,
};

int sys_eventfd2(unsigned int initval, int flags)
{
	int ret = -1;
	struct eventfd_core *ec = NULL;
	struct file_desc *desc = NULL;
	int fflags = O_RDWR;

	/* validate flags */
	if (flags & ~(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC))
		return -EINVAL;

	if (flags & EFD_CLOEXEC)
		fflags |= O_CLOEXEC;

	if (flags & EFD_NONBLOCK)
		fflags |= O_NONBLOCK;

	ec = kzalloc(sizeof(*ec));
	if (!ec)
		return -ENOMEM;

	mutex_init(&ec->lock);
	waitqueue_init(&ec->wq);
	ec->counter = initval;
	ec->semaphore = !!(flags & EFD_SEMAPHORE);

	ret = fdesc_alloc_pseudo(&desc, &eventfd_fops, fflags);
	if (ret != 0)
		goto out;

	desc->file->priv = ec;

	fdesc_publish(desc);
	return desc->fd;

out:
	kfree(ec);
	return ret;
}

/*
 * Kernel-side convenience wrapper.
 * Userspace provides its own eventfd() in user/syscall/eventfd.c.
 */
int eventfd(unsigned int initval, int flags)
{
	return sys_eventfd2(initval, flags);
}

int eventfd_read(int fd, eventfd_t *value)
{
	ssize_t rc = 0;

	if (!value)
		return -EINVAL;

	rc = sys_read(fd, value, sizeof(*value));
	if (rc < 0)
		return rc;
	if (rc != sizeof(*value))
		return -EINVAL;

	return 0;
}

int eventfd_write(int fd, eventfd_t value)
{
	ssize_t rc = 0;

	rc = sys_write(fd, &value, sizeof(value));
	if (rc < 0)
		return rc;
	if (rc != sizeof(value))
		return -EINVAL;

	return 0;
}
