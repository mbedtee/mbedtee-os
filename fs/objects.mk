# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

fs-cflags-y +=

fs-$(CONFIG_FS) += fs.o file.o
fs-$(CONFIG_FATFS) += fatfs/fatfs.o
fs-$(CONFIG_DEVFS) += devfs/devfs.o
fs-$(CONFIG_RAMFS) += ramfs/ramfs.o
fs-$(CONFIG_REEFS) += reefs/reefs.o reefs/reefs_rpc.o

ifeq ($(CONFIG_REEFS),y)
fs-$(CONFIG_RAMFS) += ramfs/ramfs_ta.o
endif

fs-$(CONFIG_TMPFS) += tmpfs/tfs.o

fs-$(CONFIG_DEBUGFS) += debugfs/debugfs.o
