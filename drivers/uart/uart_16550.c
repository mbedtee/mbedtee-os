// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * UART 16550
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

#include "uart_16550.h"

static void u16550_iowrite(struct uart_port *p, int offset, const int val)
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

static int u16550_ioread(struct uart_port *p, int offset)
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

static void u16550_putc(struct uart_port *p, const char c)
{
	u16550_iowrite(p, UART_TX, c);

	while ((u16550_ioread(p, UART_LSR) &
			(UART_LSR_THRE | UART_LSR_TEMT)) !=
			(UART_LSR_THRE | UART_LSR_TEMT))
		;
}

static void u16550_puts(struct uart_port *p, const char *str, size_t count)
{
	size_t i = 0;
	unsigned long flags = 0;

	if (count == 0)
		return;

	spin_lock_irqsave(&p->lock, flags);

	while ((str[i] != 0) &&	(i != count)) {
		if (str[i] == '\n')
			u16550_putc(p, '\r');
		u16550_putc(p, str[i++]);
	}

	spin_unlock_irqrestore(&p->lock, flags);
}

static ssize_t u16550_gets(struct uart_port *p, char *buf, size_t count)
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

static void u16550_irq_handler(struct uart_port *p)
{
	uint32_t iir = 0, lsr = 0;

	iir = u16550_ioread(p, UART_IIR);
	if ((iir & 0xF) == UART_IIR_NOINT)
		return;

	do {
		lsr = u16550_ioread(p, UART_LSR);
		if (lsr & UART_LSR_DR) {
			p->buf[p->wr] = u16550_ioread(p, UART_RX);
			if (++p->wr == sizeof(p->buf))
				p->wr = 0;
		}
	} while (lsr & UART_LSR_DR);

	wakeup(&p->wait_queue);
}

static void u16550_disable(struct uart_port *p)
{
	u16550_iowrite(p, UART_IER, 0);

	irq_unregister(p->irq);
}

static void u16550_setup(struct uart_port *p)
{
	unsigned long flags = 0;
	unsigned int div = p->clk / (p->divisor * p->baudrate);

	spin_lock_irqsave(&p->lock, flags);

	u16550_iowrite(p, UART_IER, 0);

	/* set DLAB bit */
	u16550_iowrite(p, UART_LCR, 0x80);
	/* set baudrate divisor */
	u16550_iowrite(p, UART_DLL, div & 0xFF);
	u16550_iowrite(p, UART_DLM, (div >> 8) & 0xFF);
	/* clear DLAB; set 8 bits, no parity */
	u16550_iowrite(p, UART_LCR, 0x3);
	/* enable FIFO mode, interrupt trigger by 14 bytes*/
	u16550_iowrite(p, UART_FCR, 0xC7);
	/* no modem control DTR RTS */
	u16550_iowrite(p, UART_MCR, 0x0B);
	/* set scratchpad */
	u16550_iowrite(p, UART_SCR, 0x0);

	u16550_ioread(p, UART_LSR);
	u16550_ioread(p, UART_RX);
	u16550_ioread(p, UART_IIR);
	u16550_ioread(p, UART_MSR);

	spin_unlock_irqrestore(&p->lock, flags);
}

static void u16550_attach(struct uart_port *p)
{
	u16550_setup(p);

	p->irq = irq_of_register(p->dn, p->hwirq,
		(void *)u16550_irq_handler, p);

	/* set interrupt enable reg */
	u16550_iowrite(p, UART_IER, 1);
}

static void u16550_detach(struct uart_port *p)
{
	u16550_disable(p);
}

static void u16550_suspend(struct uart_port *p)
{
	u16550_disable(p);
}

static void u16550_resume(struct uart_port *p)
{
	u16550_attach(p);
}

static const struct uart_ops u16550_port_ops = {
	.tx = u16550_puts,
	.rx = u16550_gets,
	.suspend = u16550_suspend,
	.resume = u16550_resume,
	.attach = u16550_attach,
	.detach = u16550_detach,
};

static int __init u6550_early_init(struct device_node *dn)
{
	struct uart_port *p = dev_get_drvdata(&dn->dev);

	u16550_setup(p);

	p->ops = &u16550_port_ops;

	return 0;
}
DECLARE_UART(ns16550, "ns16550", u6550_early_init);
