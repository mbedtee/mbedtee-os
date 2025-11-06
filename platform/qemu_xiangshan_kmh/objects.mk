# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)

platform-qemu_xiangshan_kmh-cflags-y +=

platform-qemu_xiangshan_kmh-$(CONFIG_QEMU_XIANGSHAN_KMH) += power.o
