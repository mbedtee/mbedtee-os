# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

platform-qemu_virt_arm-cflags-y +=

platform-qemu_virt_arm-$(CONFIG_QEMU_VIRT_ARM) += power.o
