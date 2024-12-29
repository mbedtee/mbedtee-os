// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RAMFS for TAs from REEFS
 */

#include <of.h>
#include <init.h>
#include <errno.h>
#include <trace.h>
#include <thread.h>
#include <fatfs.h>

#include <reefs_rpc.h>

#define TEEFS_DIR    "/user"
#define REEFS_BINARY  "/ta.ramfs"

static struct delayed_work dw = {0};

static struct file_system ramfs_ta = {
	.name = "ramfs",
	.mnt = {TEEFS_DIR},
	.mount = fat_mount,
	.umount = fat_umount,
	.getpath = fs_getpath,
	.putpath = fs_putpath,
};

static int ramfs_ta_mount(void)
{
	int ret = -1;
	char *argv[3] = {"auth_ta", "--auth", NULL};
	struct sched_param p = {.sched_priority =
		SCHED_HIGHPRIO_DEFAULT};

	ret = fs_mount(&ramfs_ta);
	if (ret != 0) {
		EMSG("TA ramfs mount fail\n");
		return ret;
	}

	ret = process_run("auth_ta", argv);
	if (ret < 0) {
		EMSG("run auth_ta failed\n");
		return ret;
	}

	return sched_setscheduler(ret, SCHED_RR, &p);
}

static void ramfs_ta_transfer(struct work *w)
{
	char *buff = ramfs_ta.mnt.addr;
	off_t tsize = ramfs_ta.mnt.size;
	off_t fd = -1, offset = 0;
	off_t rdbytes = 0, bsize = 0;

	fd = reefs_rpc_open(REEFS_BINARY, O_RDONLY);
	if (fd < 0) {
		DMSG("%s not ready ret %ld\n", REEFS_BINARY, fd);
		schedule_delayed_work(&dw, 200000);
		return;
	}

	while (offset < tsize) {
		bsize = min((off_t)(PAGE_SIZE * 4), tsize - offset);
		rdbytes = reefs_rpc_read(fd, buff + offset, bsize);
		if (rdbytes <= 0) {
			EMSG("rdbytes 0x%lx @ 0x%lx\n", rdbytes, bsize);
			break;
		}
		offset += rdbytes;
	}

	reefs_rpc_close(fd);

	if (offset == tsize)
		ramfs_ta_mount();
	else
		EMSG("need 0x%lx, but only recv 0x%lx\n", tsize, offset);
}

static unsigned long ramfs_ta_start(void)
{
	int ret = -1;
	static unsigned long addr;

	if (addr == 0) {
		ret = of_read_property_addr_size_by_offset(
				of_node_offset_by_compatible(0, "memory"),
				"ta-ramfs", 0, &addr, NULL);
		if (ret != 0)
			return 0;
	}
	return addr;
}

static size_t ramfs_ta_size(void)
{
	int ret = -1;
	static size_t size;

	if (size == 0) {
		ret = of_read_property_addr_size_by_offset(
				of_node_offset_by_compatible(0, "memory"),
				"ta-ramfs", 0, NULL, &size);
		if (ret != 0)
			return 0;
	}
	return size;
}

static void __init ramfs_ta_init(void)
{
	mem_register(MEM_TYPE_FS, ramfs_ta_start(), ramfs_ta_size());

	ramfs_ta.mnt.addr = phys_to_virt(ramfs_ta_start());
	ramfs_ta.mnt.size = ramfs_ta_size();

	INIT_DELAYED_WORK(&dw, ramfs_ta_transfer);
	schedule_delayed_work(&dw, 500000);
}

MODULE_INIT_LATE(ramfs_ta_init);
