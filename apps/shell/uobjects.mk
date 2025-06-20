# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

# application name
obj-$(CONFIG_USER_SHELL) += shell.elf

# application extra cflags
shell-cflags +=

# application sub-objects
shell-y += shell_user.o
