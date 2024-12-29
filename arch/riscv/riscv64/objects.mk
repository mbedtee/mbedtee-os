# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

ifeq ($(CONFIG_RISCV64),y)

arch-riscv-riscv64-cflags-y +=

arch-riscv-riscv64-y += arch-specific.o

arch-riscv-riscv64-$(CONFIG_MMU_SV39) += sv39-mmu-asm.o sv39-mmu.o

endif
