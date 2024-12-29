# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

arch-arm-common-cflags-y +=

arch-arm-common-$(CONFIG_ARM_GICV1)$(CONFIG_ARM_GICV2) += intc-gic.o
arch-arm-common-$(CONFIG_ARM_GICV3)$(CONFIG_ARM_GICV4) += intc-gic-v3.o
arch-arm-common-$(CONFIG_ARM_CCI) += cci.o
