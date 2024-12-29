# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

ifeq ($(CONFIG_RPC),y)

drivers-rpc-cflags-y += -Wstack-usage=1024

drivers-rpc-y += rpc-caller.o
drivers-rpc-y += rpc-callee-fastcall.o
drivers-rpc-$(CONFIG_RPC_YIELD) += rpc-callee.o rpc-callee-gpshm.o

drivers-rpc-$(CONFIG_AARCH32) += rpc-callee-aarch32-smc.o
drivers-rpc-$(CONFIG_AARCH64) += rpc-callee-aarch64-smc.o
drivers-rpc-$(CONFIG_RISCV) += rpc-callee-riscv-swi.o

endif