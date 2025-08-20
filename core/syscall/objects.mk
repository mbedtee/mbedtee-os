# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

core-syscall-cflags-y += -Wstack-usage=2048

core-syscall-$(CONFIG_SYSCALL) += \
	syscall.o sbrk.o mmap.o \
	fops.o utimer.o ulock.o

core-syscall-$(CONFIG_POLL) += poll.o

core-syscall-$(CONFIG_POLL) += select.o

core-syscall-$(CONFIG_EPOLL) += epoll.o

core-syscall-$(CONFIG_SPAWN) += spawn.o
core-syscall-$(CONFIG_WAITPID) += waitpid.o

core-syscall-y += signal.o
