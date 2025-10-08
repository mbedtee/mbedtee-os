# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

platform-qemu_xlnx_versal_virt-cflags-y +=

platform-qemu_xlnx_versal_virt-$(CONFIG_QEMU_XLNX_VERSAL_VIRT) += power.o
