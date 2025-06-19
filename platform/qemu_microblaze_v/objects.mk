# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)

platform-qemu_microblaze_v-cflags-y +=

platform-qemu_microblaze_v-$(CONFIG_QEMU_MICROBLAZE_V_RISCV32)$(CONFIG_QEMU_MICROBLAZE_V_RISCV64) += power.o
