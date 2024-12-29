/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * FAT FS mount/umount
 */

#ifndef _FATFS_H
#define _FATFS_H

#include <fs.h>

int fat_mount(struct file_system *fs);
int fat_umount(struct file_system *fs);

#endif
