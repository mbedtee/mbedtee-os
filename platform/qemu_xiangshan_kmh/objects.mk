# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>

platform-qemu_xiangshan_kmh-cflags-y +=

platform-qemu_xiangshan_kmh-$(CONFIG_QEMU_XIANGSHAN_KMH) += power.o
