# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

apps-shell-cflags-y +=

apps-shell-$(CONFIG_SIMPLE_SHELL) += shell.o
apps-shell-$(CONFIG_KERN_SHELL) += shell_kern.o
