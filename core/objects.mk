# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

core-cflags-y += -Wstack-usage=1024

core-y += main.o ida.o interrupt.o mem.o page.o \
	of_dtb.o of.o tevent.o ipi.o str.o kproc.o kthread.o \
	mutex.o semaphore.o assert.o workqueue.o \
	wait.o bitops.o buddy.o sleep.o delay.o

core-$(CONFIG_KMALLOC_SLAB) += kmalloc.o
core-$(CONFIG_KMALLOC_SLAB_BUDDY) += kmalloc_sb.o
core-$(CONFIG_KMALLOC_BITMAP_BUDDY) += kmalloc_bb.o

core-$(CONFIG_STACK_PROTECTOR) += stackprotector.o

core-$(CONFIG_EMBEDDED_DTB) += dtb.o

core-$(CONFIG_PRINTK) += printk.o trace.o

core-$(CONFIG_BACKTRACE) += backtrace.o

core-$(CONFIG_MMU) += vma.o kvma.o page_map.o page_scatter.o

core-$(CONFIG_VMALLOC) += vmalloc.o

core-$(CONFIG_RAMFS) += ramfs.o

core-$(CONFIG_USER) += pthread.o process_config.o process.o
