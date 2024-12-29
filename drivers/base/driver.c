// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Driver Register/Unregister
 */

#include <of.h>
#include <trace.h>
#include <driver.h>
#include <kmalloc.h>

int driver_register(const struct device_driver *drv)
{
	int ret = -1, minor = 0;
	char *path = NULL;
	struct device *dev = NULL;
	struct device_node *dn = NULL;
	const struct of_device_id *id = drv->of_match_table;

	for (; id->name; id++) {
		for_each_matching_node(dn, id) {
			dev = &dn->dev;
			dev->driver = drv;

			ret = drv->probe(dev);
			if (ret)
				continue;

			if (dev->fops == NULL)
				continue;

			path = kmalloc(DEV_MAX_NAME);
			if (path == NULL) {
				ret = -ENOMEM;
				goto err;
			}

			snprintf(path, DEV_MAX_NAME, "/dev/%s%d", drv->name, minor);

			IMSG("register %s\n", path);

			dev->path = path;
			ret = device_register(dev);
			if (ret)
				goto err;
			minor++;
		}
		dn = NULL;
	}

	return 0;

err:
	if (drv->remove)
		drv->remove(dev);
	kfree(dev->path);
	return ret;
}

void driver_unregister(const struct device_driver *drv)
{
	struct device_node *dn = NULL;
	const struct of_device_id *id = drv->of_match_table;

	for (; id->name; id++) {
		dn = of_find_matching_node(NULL, id);

		if (dn && drv->remove)
			drv->remove(&dn->dev);

		if (dn->dev.fops != NULL) {
			device_unregister(&dn->dev);
			kfree(dn->dev.path);
		}
	}
}
