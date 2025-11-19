# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)

drivers-timer-cflags-y +=

drivers-timer-$(CONFIG_TIMER) += timer.o
drivers-timer-$(CONFIG_MIPS32) += mips32-timer.o
drivers-timer-$(CONFIG_RISCV_TIMER) += riscv-timer.o
drivers-timer-$(CONFIG_CLINT_TIMER) += riscv-clint-timer.o
drivers-timer-$(CONFIG_ARMV7_GENERIC_TIMER) += armv7-generic-timer.o
drivers-timer-$(CONFIG_ARMV7_GLOBAL_TIMER) += armv7-global-timer.o
drivers-timer-$(CONFIG_ARMV7_PRIVATE_TIMER) += armv7-private-timer.o
drivers-timer-$(CONFIG_ARMV8_GENERIC_TIMER) += armv8-timer.o
drivers-timer-$(CONFIG_XLNX_TIMER) += xlnx-timer.o
