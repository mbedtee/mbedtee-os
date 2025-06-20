# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

user-tee-cflags-y +=

user-tee-uobjs-$(CONFIG_TEE_API) += \
	tee_api.o \
	tee_property.o \
	tee_object.o \
	tee_crypto.o \
	tee_arith.o