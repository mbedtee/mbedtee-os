# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

arch-mips-common-cflags-y +=

arch-mips-common-$(CONFIG_MIPS) += intc-mips.o
