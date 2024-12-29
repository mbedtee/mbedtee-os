# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

lib-fdt-cflags-y +=

lib-fdt-$(CONFIG_FDT_LIB) += fdt.o fdt_addresses.o \
	fdt_empty_tree.o fdt_ro.o fdt_rw.o \
	fdt_strerror.o fdt_sw.o fdt_wip.o
