# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

# application name
obj-$(CONFIG_MBEDTEST) += mbedtest.elf

# application extra cflags
mbedtest-cflags +=

# application sub-objects
mbedtest-y += mbedtest.o
