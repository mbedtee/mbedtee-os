// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Device Register/Unregister
 */

#include <trace.h>
#include <driver.h>
#include <strmisc.h>
#include <sections.h>

#include <devfs.h>

int device_register(struct device *dev)
{
	int ret = -EINVAL;
	struct file_system *fs = NULL;

	if (dev == NULL || dev->fops == NULL)
		return -EINVAL;

	fs = fs_get(dev->path);
	if (fs == NULL)
		return -ENODEV;

	ret = devfs_create(fs, dev);

	fs_put(fs);
	return ret;
}

int device_unregister(struct device *dev)
{
	struct file_system *fs = NULL;

	if (dev == NULL)
		return -EINVAL;

	fs = fs_get(dev->path);
	if (fs == NULL)
		return -ENODEV;

	devfs_remove(fs, dev);

	fs_put(fs);
	return 0;
}

void modules_init(void)
{
	int cnt = 0;
	init_func_t func = NULL;
	unsigned long ptr = 0;
	unsigned long module_s = 0, module_e = 0;

	module_s = __mod_init_start();
	module_e = __mod_init_end();

	for (ptr = module_s; ptr < module_e;
			ptr += sizeof(unsigned long)) {
		func = *(init_func_t *)ptr;
		if (func) {
			func();
			cnt++;
		}
	}

	IMSG("initialized %d modules!\n", cnt);
}

void early_init(void)
{
	int cnt = 0;
	init_func_t func = NULL;
	unsigned long module_s = 0, module_e = 0;
	unsigned long func_ptr = 0, func_val = 0;

	module_s = __early_init_start();
	module_e = __early_init_end();

	for (func_ptr = module_s; func_ptr < module_e;
			func_ptr += sizeof(unsigned long)) {
		func_val = *(unsigned long *)func_ptr;
		if (func_val != 0) {
			func = (init_func_t)func_val;
			func();
			cnt++;
		}
	}

	IMSG("initialized %d modules!\n", cnt);
}

void percpu_init(void)
{
	int cnt = 0;
	init_func_t func = NULL;
	unsigned long module_s = 0, module_e = 0;
	unsigned long func_ptr = 0, func_val = 0;

	module_s = __percpu_init_start();
	module_e = __percpu_init_end();

	for (func_ptr = module_s; func_ptr < module_e;
			func_ptr += sizeof(unsigned long)) {
		func_val = *(unsigned long *)func_ptr;
		if (func_val != 0) {
			func = (init_func_t)func_val;
			func();
			cnt++;
		}
	}

	IMSG("initialized %d modules!\n", cnt);
}
