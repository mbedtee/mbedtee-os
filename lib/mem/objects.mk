# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

lib-mem-cflags-y +=

lib-mem-y += memcmp.o memcpy.o memset.o memmove.o

lib-mem-uobjs-$(CONFIG_USER) = memcmp.o
