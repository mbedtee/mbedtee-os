# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

ifeq ($(CONFIG_AARCH64),y)

arch-arm-aarch64-cflags-y += -Wstack-usage=1024

arch-arm-aarch64-y = cache.o exception.o percpu.o lockdep.o \
	atomic.o arch-specific.o aarch64-start.o aarch64-cache.o \
	aarch64-secondary-cpu.o aarch64-exception.o aarch64-ctx.o \
	aarch64-monitor.o aarch64-monitor-ctx.o aarch64-monitor-exception.o	

arch-arm-aarch64-$(CONFIG_REE) += ree.o

arch-arm-aarch64-$(CONFIG_MMU) += aarch64-mmu.o aarch64-mmu-asm.o

arch-arm-aarch64-$(CONFIG_ARMV8_GENERIC_TIMER) += armv8-timer.o

ifneq ($(CONFIG_KERN_NEWLIB),y)
arch-arm-aarch64-y += memcpy.o memset.o
endif

endif