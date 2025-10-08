// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * UART PL011
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

#include "uart_pl011.h"

static void pl011_putc(struct uart_port *p, const char c)
{
	while (ioread32(p->membase + PL011_FR) & PL011_FR_TXFF)
		;

	iowrite32(c, p->membase + PL011_DR);

	while (ioread32(p->membase + PL011_FR) & PL011_FR_BUSY)
		;
}

static void pl011_puts(struct uart_port *p, const char *str, size_t count)
{
	size_t i = 0;
	unsigned long flags = 0;

	if (count == 0)
		return;

	spin_lock_irqsave(&p->lock, flags);

	while ((str[i] != 0) && (i != count)) {
		if (str[i] == '\n')
			pl011_putc(p, '\r');
		pl011_putc(p, str[i++]);
	}

	spin_unlock_irqrestore(&p->lock, flags);
}

static ssize_t pl011_gets(struct uart_port *p, char *buf, size_t count)
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

static void pl011_irq_handler(struct uart_port *p)
{
	uint32_t imsc = 0, fr = 0;
	uint32_t stat = 0, c = 0;

	imsc = ioread32(p->membase + PL011_IMSC);
	stat = ioread32(p->membase + PL011_RIS) & imsc;
	if (stat == 0)
		return;

	do {
		/* clear other interrupts */
		iowrite32(stat & ~(PL011_RTIC | PL011_RXIC),
				p->membase + PL011_ICR);

		/* Try to get data from FIFO */
		if (stat & (PL011_RTIC | PL011_RXIC)) {
			fr = ioread32(p->membase + PL011_FR);
			if ((fr & PL011_FR_RXFE) == 0) {
				c = ioread32(p->membase + PL011_DR);
				p->buf[p->wr++] = c & 0xff;
				if (p->wr == sizeof(p->buf))
					p->wr = 0;
			} else {
				break;
			}
		}

		stat = ioread32(p->membase + PL011_RIS) & imsc;
	} while (stat);

	wakeup(&p->wait_queue);
}

static void pl011_disable(struct uart_port *p)
{
	/*
	 * Disable all
	 */
	iowrite32(0, p->membase + PL011_CR);
	irq_unregister(p->irq);
}

static void pl011_setup(struct uart_port *p)
{
	uint32_t brd_i = 0;
	uint32_t brd_f = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&p->lock, flags);

	/*
	 * Disable all
	 */
	iowrite32(0, p->membase + PL011_CR);

	/* mask/clear all interrupt */
	iowrite32(0, p->membase + PL011_IMSC);
	iowrite32(PL011_OEIC | PL011_BEIC | PL011_PEIC |
				PL011_FEIC | PL011_RTIC | PL011_RXIC,
			p->membase + PL011_ICR);

	/* Baud rate divisor
	 *	BAUDDIV = (FUARTCLK/ {16 * Baud rate})
	 *  fractional part, m = integer((x * 64) + 0.5)
	 */
	brd_i = p->clk * 64 / (p->baudrate * p->divisor);
	brd_f = brd_i & 0x3F;
	brd_i >>= 6;
	iowrite32(brd_i, p->membase + PL011_IBRD);
	iowrite32(brd_f, p->membase + PL011_FBRD);

	/*
	 * 8-bit data, 1-bit stop, none-parity, with FIFO
	 */
	iowrite32(PL011_LCRH_WLEN_8 | PL011_LCRH_FEN,
				p->membase + PL011_LCRH);
	iowrite32(PL011_IFLS_RX4_8 | PL011_IFLS_TX4_8,
				p->membase + PL011_IFLS);

	/*
	 * Enable UART with TX, without interrupt
	 */
	iowrite32(PL011_CR_UARTEN | PL011_CR_TXE,
				p->membase + PL011_CR);

	spin_unlock_irqrestore(&p->lock, flags);

}

static void pl011_attach(struct uart_port *p)
{
	pl011_setup(p);

	p->irq = irq_of_register(p->dn, p->hwirq,
		(void *)pl011_irq_handler, p);

	/*
	 * Enable RX and RX interrupt
	 */
	iowrite32(ioread32(p->membase + PL011_CR) |
			PL011_CR_RXE, p->membase + PL011_CR);
	iowrite32(PL011_RTIM | PL011_RXIM,
				p->membase + PL011_IMSC);
}

static void pl011_detach(struct uart_port *p)
{
	pl011_disable(p);
}

static void pl011_suspend(struct uart_port *p)
{
	pl011_disable(p);
}

static void pl011_resume(struct uart_port *p)
{
	pl011_attach(p);
}

static const struct uart_ops pl011_port_ops = {
	.tx = pl011_puts,
	.rx = pl011_gets,
	.suspend = pl011_suspend,
	.resume = pl011_resume,
	.attach = pl011_attach,
	.detach = pl011_detach,
};

static int __init pl011_early_init(struct device_node *dn)
{
	struct uart_port *p = dev_get_drvdata(&dn->dev);

	pl011_setup(p);

	p->ops = &pl011_port_ops;

	return 0;
}
DECLARE_UART(pl011, "arm,pl011", pl011_early_init);
