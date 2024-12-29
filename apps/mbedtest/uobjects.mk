# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

# application name
obj-$(CONFIG_MBEDTEST) += mbedtest.elf

# application extra cflags
mbedtest-cflags +=

# application sub-objects
mbedtest-y += mbedtest.o
