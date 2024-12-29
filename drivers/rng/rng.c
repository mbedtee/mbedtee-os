// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RNG framework
 */

#include <io.h>
#include <of.h>
#include <rng.h>
#include <str.h>
#include <list.h>
#include <sched.h>
#include <trace.h>
#include <driver.h>

static struct {
	const struct rng_struct *rng;
	struct device dev;
} rng_desc = {NULL};

void rng_register(const struct rng_struct *r)
{
	rng_desc.rng = r;
}

static const struct rng_struct *rng_current(void)
{
	return rng_desc.rng;
}

static int rng_open(struct file *f, mode_t mode, void *arg)
{
	const struct rng_struct *p = rng_current();

	if (p == NULL)
		return -ENODEV;

	if (f->flags & O_ACCMODE)
		return -EACCES;

	f->priv = (void *)p;

	return 0;
}

static int rng_close(struct file *f)
{
	if (f->priv == NULL)
		return -ENODEV;

	f->priv = NULL;
	return 0;
}

static ssize_t rng_read(struct file *f,
	void *buf, size_t count)
{
	const struct rng_struct *p = f->priv;

	if (p == NULL)
		return -ENODEV;

	if (buf == NULL)
		return -EINVAL;

	return p->read(p, buf, count);
}

static int rng_suspend(struct device *dev)
{
	const struct rng_struct *p = rng_current();

	if (p && p->suspend) {
		p->suspend(p);
		return 0;
	}

	return -ENODEV;
}

static int rng_resume(struct device *dev)
{
	const struct rng_struct *p = rng_current();

	if (p && p->resume) {
		p->resume(p);
		return 0;
	}

	return -ENODEV;
}

static const struct file_operations rng_fops = {
	.open = rng_open,
	.close = rng_close,
	.read = rng_read,
};

static const struct str_operations rng_str = {
	.suspend = rng_suspend,
	.resume = rng_resume,
};

static void __init rng_init(void)
{
	struct device *dev = &rng_desc.dev;

	dev->fops = &rng_fops;
	dev->sops = &rng_str;
	dev->path = "/dev/urandom";

	device_register(dev);
}

MODULE_INIT_SYS(rng_init);
