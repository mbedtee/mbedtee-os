/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * UART interface for kernel
 */

#ifndef _UART_H
#define _UART_H

#include <stddef.h>
#include <interrupt.h>
#include <workqueue.h>

#include <generated/autoconf.h>

#define UART_BUFFER_SIZE (888)

struct uart_port {
	int idx;
	unsigned int irq;
	unsigned int clk;
	unsigned int divisor;
	unsigned int baudrate;
	unsigned char regshift;
	unsigned char regiowidth;
	struct spinlock lock;
	unsigned int rd, wr;
	void *membase;
	unsigned long iobase;
	size_t iosize;
	struct tevent tevent;
	struct waitqueue wait_queue;
	struct device_node *dn;
	const struct uart_ops *ops;
	struct list_head node;
	unsigned char buf[UART_BUFFER_SIZE];
};

struct uart_ops {
	void (*tx)(struct uart_port *p, const char *str, size_t cnt);
	ssize_t (*rx)(struct uart_port *p, char *str, size_t cnt);
	ssize_t (*poll_rx)(struct uart_port *p);
	void (*suspend)(struct uart_port *p);
	void (*resume)(struct uart_port *p);
	void (*attach)(struct uart_port *p);
	void (*detach)(struct uart_port *p);
};

#define DECLARE_UART(name, compatible, initfn)                 \
	static const struct of_compat_init __of_uart_##name        \
		__of_uartinit = {.compat = (compatible), .init = (initfn)}

void uart_early_init(void);
void uart_early_puts(const char *str, size_t cnt);

int uart_register(struct uart_port *p);
void uart_unregister(struct uart_port *p);

#endif
