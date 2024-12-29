# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

platform-qemu_virt_riscv32-cflags-y +=

platform-qemu_virt_riscv32-$(CONFIG_QEMU_VIRT_RISCV32) += power.o
