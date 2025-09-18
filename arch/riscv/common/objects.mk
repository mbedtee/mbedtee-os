# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>

arch-riscv-common-cflags-y += -Wstack-usage=1024

arch-riscv-common-$(CONFIG_RISCV) = \
	riscv-start.o riscv-exception.o riscv-ctx.o riscv-pmp.o \
	riscv-secondary-cpu.o intc-riscv.o riscv-cache.o \
	lockdep.o atomic.o percpu.o cache.o exception.o

arch-riscv-common-$(CONFIG_MMU_SV32)$(CONFIG_MMU_SV39) += riscv-tlb.o