# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

# application name
obj-$(CONFIG_AUTH_TA) += auth_ta.elf

# application extra cflags
auth_ta-cflags +=

# application sub-objects
auth_ta-y += auth_ta.o
