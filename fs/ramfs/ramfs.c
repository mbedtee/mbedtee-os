// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * root RAMFS @ "/" (based on FATFS)
 */

#include <fs.h>
#include <fatfs.h>
#include <trace.h>
#include <init.h>

static struct file_system ramfs_root = {
	.name = "ramfs",
	.mnt = {"/", NULL, 0},
	.mount = fat_mount,
	.umount = fat_umount,
	.getpath = fs_getpath,
	.putpath = fs_putpath,
};

static void __init ramfs_root_init(void)
{
	ramfs_root.mnt.addr = (void *)__ramfs_start();
	ramfs_root.mnt.size = __ramfs_size();

	assert(fs_mount(&ramfs_root) == 0);
}
EARLY_INIT_ROOT(ramfs_root_init);
