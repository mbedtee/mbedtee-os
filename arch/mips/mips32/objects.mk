# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

ifeq ($(CONFIG_MIPS32),y)

arch-mips-mips32-cflags-y += -Wstack-usage=1024

arch-mips-mips32-$(CONFIG_MIPS32) = mips32-start.o \
	mips32-exception.o mips32-ctx.o lockdep.o exception.o \
	mips32-timer.o mips32-cache.o atomic.o percpu.o \
	cache.o arch-specific.o

arch-mips-mips32-$(CONFIG_MMU) += mips32-mmu.o mips32-mmu-asm.o mips32-tlb.o

endif
