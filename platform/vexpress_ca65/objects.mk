# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

platform-vexpress_ca65-cflags-y +=

platform-vexpress_ca65-$(CONFIG_VEXPRESS_CA65) += power.o
