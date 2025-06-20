# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>

platform-qemu_imx8mp-cflags-y +=

platform-qemu_imx8mp-$(CONFIG_QEMU_IMX8MP) += power.o
