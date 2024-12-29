# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

ifeq ($(CONFIG_AARCH32),y)

arch-arm-aarch32-cflags-y += -Wstack-usage=1024

arch-arm-aarch32-y = aarch32-start.o cache.o exception.o percpu.o atomic.o \
	aarch32-cache.o aarch32-ctx.o lockdep.o arch-specific.o \
	aarch32-secondary-cpu.o aarch32-monitor.o aarch32-exception.o

ifneq ($(CONFIG_KERN_NEWLIB),y)
arch-arm-aarch32-y += memcpy.o memset.o
endif

arch-arm-aarch32-$(CONFIG_REE) += ree.o

arch-arm-aarch32-$(CONFIG_MMU) += aarch32-mmu.o aarch32-mmu-asm.o

arch-arm-aarch32-$(CONFIG_ARMV7_GENERIC_TIMER) += armv7-generic-timer.o
arch-arm-aarch32-$(CONFIG_ARMV7_GLOBAL_TIMER) += armv7-global-timer.o
arch-arm-aarch32-$(CONFIG_ARMV7_PRIVATE_TIMER) += armv7-private-timer.o

endif
