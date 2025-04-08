// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * Cadence UART driver - QEMU xlnx-zynqmp
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

#include "uart_cdns.h"

static void cdns_putc(struct uart_port *p, const char c)
{
	while (ioread32(p->membase + CDNS_SR) & CDNS_SR_TXFULL)
		;

	iowrite32(c, p->membase + CDNS_FIFO);
}

static void cdns_puts(struct uart_port *p, const char *str, size_t count)
{
	size_t i = 0;
	unsigned long flags = 0;

	if (count == 0)
		return;

	spin_lock_irqsave(&p->lock, flags);

	while ((str[i] != 0) && (i != count)) {
		if (str[i] == '\n')
			cdns_putc(p, '\r');
		cdns_putc(p, str[i++]);
	}

	spin_unlock_irqrestore(&p->lock, flags);
}

static ssize_t cdns_gets(struct uart_port *p, char *buf, size_t count)
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

static void cdns_irq_handler(struct uart_port *p)
{
	uint32_t stat = 0, c = 0;

	stat = ioread32(p->membase + CDNS_ISR);
	iowrite32(stat, p->membase + CDNS_ISR);

	if ((stat & (CDNS_IER_TOUT | CDNS_IER_FRAMING |
			CDNS_IER_OVERRUN | CDNS_IER_RXTRIG)) == 0)
		return;

	do {
		/* check RX FIFO */
		if (!(ioread32(p->membase + CDNS_SR) & CDNS_SR_RXEMPTY)) {
			c = ioread32(p->membase + CDNS_FIFO);
			p->buf[p->wr++] = c & 0xff;
			if (p->wr == sizeof(p->buf))
				p->wr = 0;
		} else {
			break;
		}
	} while (1);

	wakeup(&p->wait_queue);
}

static void cdns_disable(struct uart_port *p)
{
	/*
	 * Disable all
	 */
	iowrite32(0, p->membase + CDNS_CR);
	irq_unregister(p->irq);
}

static void cdns_setup(struct uart_port *p)
{
	uint32_t bdiv = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&p->lock, flags);

	/*
	 * Disable all
	 */
	iowrite32(CDNS_CR_RXRST | CDNS_CR_TXRST,
		p->membase + CDNS_CR);

	/* Disable all interrupt */
	iowrite32(0, p->membase + CDNS_IER);

	/*
	 * 8-bit data, 1-bit stop, none-parity
	 */
	iowrite32(CDNS_MR_CHARLEN_8_BIT | CDNS_MR_STOPMODE_1_BIT |
		CDNS_MR_CHMODE_NORM | CDNS_MR_PARITY_NONE |
		CDNS_MR_CLKSEL, p->membase + CDNS_MR);

	/* Baud rate divisor
	 *	BAUDDIV + 1 = (UARTCLK/ {8 * Baud rate})
	 */
	bdiv = p->clk / (p->baudrate * p->divisor) - 1;
	iowrite32(8, p->membase + CDNS_BAUDGEN);
	iowrite32(bdiv, p->membase + CDNS_BAUDDIV);

	iowrite32(56, p->membase + CDNS_RXWM);
	iowrite32(10, p->membase + CDNS_RXTOUT);

	/* clear all pending interrupt */
	iowrite32(ioread32(p->membase + CDNS_ISR),
			p->membase + CDNS_ISR);

	/*
	 * Enable UART with TX, without interrupt
	 */
	iowrite32(CDNS_CR_TXE, p->membase + CDNS_CR);

	spin_unlock_irqrestore(&p->lock, flags);

}

static void cdns_attach(struct uart_port *p)
{
	cdns_setup(p);

	p->irq = irq_of_register(p->dn, p->hwirq,
		(void *)cdns_irq_handler, p);

	/*
	 * Enable RX and RX interrupt
	 */
	iowrite32(ioread32(p->membase + CDNS_CR) |
			CDNS_CR_RXE, p->membase + CDNS_CR);
	iowrite32(CDNS_IER_TOUT | CDNS_IER_FRAMING |
			CDNS_IER_OVERRUN | CDNS_IER_RXTRIG,
			p->membase + CDNS_IER);
}

static void cdns_detach(struct uart_port *p)
{
	cdns_disable(p);
}

static void cdns_suspend(struct uart_port *p)
{
	cdns_disable(p);
}

static void cdns_resume(struct uart_port *p)
{
	cdns_attach(p);
}

static const struct uart_ops cdns_port_ops = {
	.tx = cdns_puts,
	.rx = cdns_gets,
	.suspend = cdns_suspend,
	.resume = cdns_resume,
	.attach = cdns_attach,
	.detach = cdns_detach,
};

static int __init cdns_early_init(struct device_node *dn)
{
	struct uart_port *p = dev_get_drvdata(&dn->dev);

	cdns_setup(p);

	p->ops = &cdns_port_ops;

	return 0;
}
DECLARE_UART(cdns, "cadence,uart", cdns_early_init);
