/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Device Register Framework
 */

#ifndef _DEVICE_H
#define _DEVICE_H

#include <fs.h>
#include <str.h>
#include <init.h>
#include <list.h>
#include <stdint.h>

#define DEV_MAX_NAME (64u)

struct device {
	const char *path;
	const struct file_operations *fops;
	const struct str_operations *sops;

	const struct device_driver *driver;
	void *driver_data;
	void *fs_data;
};

int device_register(struct device *dev);
int device_unregister(struct device *dev);

static inline void dev_set_drvdata(
	struct device *dev, void *data)
{
	dev->driver_data = data;
}

static inline void *dev_get_drvdata(
	struct device *dev)
{
	return dev->driver_data;
}

void early_init(void);
void percpu_init(void);
void modules_init(void);

#endif
