# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)

platform-qemu_virt_riscv32_imsic-cflags-y +=

platform-qemu_virt_riscv32_imsic-$(CONFIG_QEMU_VIRT_RISCV32_IMSIC) += power.o
