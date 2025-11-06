# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)

platform-qemu_virt_riscv64_imsic-cflags-y +=

platform-qemu_virt_riscv64_imsic-$(CONFIG_QEMU_VIRT_RISCV64_IMSIC) += power.o
