# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

platform-qemu_xlnx_zcu102-cflags-y +=

platform-qemu_xlnx_zcu102-$(CONFIG_QEMU_XLNX_ZCU102) += power.o
