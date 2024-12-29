# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

core-misc-cflags-y +=

core-misc-y += misc.o ktime.o

core-misc-$(CONFIG_KERN_NEWLIB) += stubs.o
