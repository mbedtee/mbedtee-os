# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

platform-qemu_virt_aarch64-cflags-y +=

platform-qemu_virt_aarch64-$(CONFIG_QEMU_VIRT_AARCH64) += power.o
