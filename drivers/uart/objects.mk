# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

drivers-uart-cflags-y +=

drivers-uart-$(CONFIG_UART) += uart.o
drivers-uart-$(CONFIG_UART_16550) += uart_16550.o
drivers-uart-$(CONFIG_UART_PL011) += uart_pl011.o
drivers-uart-$(CONFIG_UART_SIFIVE) += uart_sifive.o