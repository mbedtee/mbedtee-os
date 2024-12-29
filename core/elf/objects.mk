# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

ifeq ($(CONFIG_ELF_LOADER),y)

core-elf-cflags-y += -Wstack-usage=1024

core-elf-y += elf.o
core-elf-y += elf_proc.o

core-elf-$(CONFIG_AARCH32) += elf_aarch32.o
core-elf-$(CONFIG_AARCH64) += elf_aarch64.o
core-elf-$(CONFIG_MIPS32) += elf_mips32.o
core-elf-$(CONFIG_RISCV) += elf_riscv.o

endif
