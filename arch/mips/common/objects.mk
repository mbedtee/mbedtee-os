# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

arch-mips-common-cflags-y +=

arch-mips-common-$(CONFIG_MIPS) += intc-mips.o
