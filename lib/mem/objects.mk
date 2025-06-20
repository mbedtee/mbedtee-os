# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

lib-mem-cflags-y +=

lib-mem-y += memcmp.o

lib-mem-uobjs-$(CONFIG_USER) = memcmp.o

ifneq ($(CONFIG_KERN_NEWLIB),y)
lib-mem-y += memcpy.o memset.o memmove.o
endif
