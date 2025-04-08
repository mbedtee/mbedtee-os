# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)

platform-qemu_raspi4b-cflags-y +=

platform-qemu_raspi4b-$(CONFIG_QEMU_RASPI4B) += power.o
