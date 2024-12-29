# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

core-sched-cflags-y += -Wstack-usage=1024

core-sched-y += sched.o sched_signal.o \
	sched_prio.o sched_record.o \
	thread_info.o sched_tasklet.o \
	sched_timeout.o

core-sched-$(CONFIG_AARCH32) += sched_aarch32.o
core-sched-$(CONFIG_AARCH64) += sched_aarch64.o
core-sched-$(CONFIG_MIPS32) += sched_mips32.o
core-sched-$(CONFIG_RISCV) += sched_riscv.o

core-sched-$(CONFIG_USER) += sched_cputime.o
core-sched-$(CONFIG_DEBUGFS) += sched_debugfs.o
