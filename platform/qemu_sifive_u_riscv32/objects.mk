# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

platform-qemu_sifive_u_riscv32-cflags-y +=

platform-qemu_sifive_u_riscv32-$(CONFIG_QEMU_SIFIVE_U_RISCV32) += power.o
