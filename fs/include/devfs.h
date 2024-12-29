/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Device FS Framework
 */

#ifndef _DEVICE_FS_H
#define _DEVICE_FS_H

#include <device.h>

int devfs_create(struct file_system *fs, struct device *dev);
void devfs_remove(struct file_system *fs, struct device *dev);

#endif
