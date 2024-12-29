# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

lib-string-cflags-y +=

lib-string-y += strmisc.o

ifneq ($(CONFIG_KERN_NEWLIB),y)
lib-string-y += string.o
endif
