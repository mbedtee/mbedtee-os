// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * SiFive UART
 */

#include <io.h>
#include <of.h>
#include <str.h>
#include <kmap.h>
#include <uart.h>
#include <sched.h>
#include <trace.h>
#include <device.h>
#include <kmalloc.h>
#include <interrupt.h>

#include "uart_sifive.h"

static void uart_sifive_iowrite(struct uart_port *p, int offset, const int val)
{
	int regoff = offset << p->regshift;

	switch (p->regiowidth) {
	case 1:
		iowrite8(val, p->membase + regoff);
		break;
	case 2:
		iowrite16(val, p->membase + regoff);
		break;
	default:
		iowrite32(val, p->membase + regoff);
		break;
	}
}

static int uart_sifive_ioread(struct uart_port *p, int offset)
{
	int regoff = offset << p->regshift, val = 0;

	switch (p->regiowidth) {
	case 1:
		val = ioread8(p->membase + regoff);
		break;
	case 2:
		val = ioread16(p->membase + regoff);
		break;
	default:
		val = ioread32(p->membase + regoff);
		break;
	}

	return val;
}

static void uart_sifive_putc(struct uart_port *p, const char c)
{
	while (uart_sifive_ioread(p, UART_TXFIFO) & UART_TXFULL)
		;

	uart_sifive_iowrite(p, UART_TXFIFO, c);
}

static void uart_sifive_puts(struct uart_port *p, const char *str, size_t count)
{
	size_t i = 0;
	unsigned long flags = 0;

	if (count == 0)
		return;

	spin_lock_irqsave(&p->lock, flags);

	while ((str[i] != 0) &&	(i != count)) {
		if (str[i] == '\n')
			uart_sifive_putc(p, '\r');
		uart_sifive_putc(p, str[i++]);
	}

	spin_unlock_irqrestore(&p->lock, flags);
}

static ssize_t uart_sifive_gets(struct uart_port *p, char *buf, size_t count)
{
	size_t pos = 0;
	unsigned long flags = 0;

	if (count == 0)
		return 0;

	spin_lock_irqsave(&p->lock, flags);
	while ((p->rd != p->wr) && (pos < count)) {
		buf[pos++] = p->buf[p->rd++];
		if (p->rd == sizeof(p->buf))
			p->rd = 0;
	}

	buf[pos] = 0;
	spin_unlock_irqrestore(&p->lock, flags);
	return pos;
}

static void uart_sifive_irq_handler(struct uart_port *p)
{
	unsigned int ip = 0, rxval = 0;

	ip = uart_sifive_ioread(p, UART_IP);
	if (ip == 0) /* no interrupt */
		return;

	if (!(ip & UART_IPRX)) /* not for Rx */
		return;

	do {
		rxval = uart_sifive_ioread(p, UART_RXFIFO);

		if (rxval & UART_RXEMPTY)
			break;

		p->buf[p->wr] = rxval & 0xff;
		if (++p->wr == sizeof(p->buf))
			p->wr = 0;
	} while (1);

	wakeup(&p->wait_queue);
}

static void uart_sifive_disable(struct uart_port *p)
{
	uart_sifive_iowrite(p, UART_IE, 0);

	irq_unregister(p->irq);
}

/**
 * Find minimum divisor divides in_freq to max_target_hz;
 * Based on uart driver in SiFive FSBL.
 *
 * f_baud = f_in / (div + 1) => div = (f_in / f_baud) - 1
 * The nearest integer solution requires rounding up as to not exceed max_target_hz.
 * div  = ceil(f_in / f_baud) - 1
 *	= floor((f_in - 1 + f_baud) / f_baud) - 1
 * This should not overflow as long as (f_in - 1 + f_baud) does not exceed
 * 2^32 - 1, which is unlikely since we represent frequencies in kHz.
 */
static inline unsigned int uart_sifive_divisor(uint64_t in_freq,
						uint64_t max_target_hz)
{
	uint64_t quotient = (in_freq + max_target_hz - 1) / (max_target_hz);

	/* Avoid underflow */
	if (quotient == 0)
		return 0;
	else
		return quotient - 1;
}

static void uart_sifive_setup(struct uart_port *p)
{
	unsigned long flags = 0;
	unsigned int div = uart_sifive_divisor(p->clk, p->baudrate);

	spin_lock_irqsave(&p->lock, flags);

	/* disable interrupt */
	uart_sifive_iowrite(p, UART_IE, 0);

	/* set baudrate divisor */
	uart_sifive_iowrite(p, UART_DIV, div);

	/* Enable Tx */
	uart_sifive_iowrite(p, UART_TXCTRL, UART_TXEN);

	/* Enable Rx */
	uart_sifive_iowrite(p, UART_RXCTRL, UART_RXEN);

	spin_unlock_irqrestore(&p->lock, flags);
}

static void uart_sifive_attach(struct uart_port *p)
{
	uart_sifive_setup(p);

	p->irq = irq_of_register(p->dn, p->hwirq,
		(void *)uart_sifive_irq_handler, p);

	/* set interrupt enable register */
	uart_sifive_iowrite(p, UART_IE, UART_IERX);
}

static void uart_sifive_detach(struct uart_port *p)
{
	uart_sifive_disable(p);
}

static void uart_sifive_suspend(struct uart_port *p)
{
	uart_sifive_disable(p);
}

static void uart_sifive_resume(struct uart_port *p)
{
	uart_sifive_attach(p);
}

static const struct uart_ops uart_sifive_port_ops = {
	.tx = uart_sifive_puts,
	.rx = uart_sifive_gets,
	.suspend = uart_sifive_suspend,
	.resume = uart_sifive_resume,
	.attach = uart_sifive_attach,
	.detach = uart_sifive_detach,
};

static int __init uart_sifive_early_init(struct device_node *dn)
{
	struct uart_port *p = dev_get_drvdata(&dn->dev);

	uart_sifive_setup(p);

	p->ops = &uart_sifive_port_ops;

	return 0;
}
DECLARE_UART(sifive, "sifive", uart_sifive_early_init);
