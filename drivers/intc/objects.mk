# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

drivers-intc-cflags-y +=

drivers-intc-$(CONFIG_INTEL_I8259) += intc-i8259.o
drivers-intc-$(CONFIG_RISCV_PLIC) += intc-plic.o
drivers-intc-$(CONFIG_RISCV_APLIC) += intc-aplic.o
drivers-intc-$(CONFIG_RISCV_IMSIC) += intc-imsic.o
drivers-intc-$(CONFIG_SALIX_MIPS_INTC) += intc-salix-mips.o
drivers-intc-$(CONFIG_SALIX_ARM_INTC) += intc-salix-arm.o
drivers-intc-$(CONFIG_ASPEED_AST2700_INTC) += intc-aspeed-ast2700.o
