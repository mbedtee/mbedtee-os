# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

ifeq ($(CONFIG_RISCV32),y)

arch-riscv-riscv32-cflags-y +=

arch-riscv-riscv32-y += arch-specific.o

arch-riscv-riscv32-$(CONFIG_MMU_SV32) += sv32-mmu-asm.o sv32-mmu.o

endif
