# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

platform-qemu_virt_riscv64-cflags-y +=

platform-qemu_virt_riscv64-$(CONFIG_QEMU_VIRT_RISCV64) += power.o
