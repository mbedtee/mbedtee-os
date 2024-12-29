# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

drivers-globalplatform-cflags-y +=

drivers-globalplatform-$(CONFIG_GLOBALPLATFORM) += globalplatform.o ipc.o
