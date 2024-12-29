# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

core-syscall-cflags-y += -Wstack-usage=2048

core-syscall-$(CONFIG_SYSCALL) += \
	syscall.o sbrk.o mmap.o poll.o \
	epoll.o fops.o utimer.o ulock.o

core-syscall-y += signal.o
