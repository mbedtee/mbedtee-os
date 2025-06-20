# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>

platform-qemu_virt_riscv64_aplic-cflags-y +=

platform-qemu_virt_riscv64_aplic-$(CONFIG_QEMU_VIRT_RISCV64_APLIC) += power.o
