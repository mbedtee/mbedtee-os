# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

user-syscall-cflags-y +=

user-syscall-uobjs-$(CONFIG_SYSCALL) += \
	stubs.o dirent.o lock.o sched.o \
	sleep.o ioctl.o dup.o mmap.o time.o \
	poll.o mqueue.o shm.o

user-syscall-uobjs-$(CONFIG_EPOLL) += epoll.o

user-syscall-uobjs-$(CONFIG_SIGNAL) += signal.o

ifeq ($(CONFIG_SYSCALL),y)
user-syscall-uobjs-$(CONFIG_MIPS32) += syscall-mips32.o
user-syscall-uobjs-$(CONFIG_AARCH32) += syscall-aarch32.o
user-syscall-uobjs-$(CONFIG_AARCH64) += syscall-aarch64.o
user-syscall-uobjs-$(CONFIG_RISCV32) += syscall-riscv32.o
user-syscall-uobjs-$(CONFIG_RISCV64) += syscall-riscv64.o
endif
