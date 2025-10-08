// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * IMX UART driver
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

#include "uart_imx.h"

static void imx_putc(struct uart_port *p, const char c)
{
	while (ioread32(p->membase + IMX_UTS) & IMX_UTS_TXFULL)
		;

	iowrite32(c, p->membase + IMX_TX);
}

static void imx_puts(struct uart_port *p, const char *str, size_t count)
{
	size_t i = 0;
	unsigned long flags = 0;

	if (count == 0)
		return;

	spin_lock_irqsave(&p->lock, flags);

	while ((str[i] != 0) && (i != count)) {
		if (str[i] == '\n')
			imx_putc(p, '\r');
		imx_putc(p, str[i++]);
	}

	spin_unlock_irqrestore(&p->lock, flags);
}

static ssize_t imx_gets(struct uart_port *p, char *buf, size_t count)
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

static void imx_irq_handler(struct uart_port *p)
{
	uint32_t rx = 0;

	while ((rx = ioread32(p->membase + IMX_RX)) & IMX_RX_CHARRDY) {
		if (!unlikely(rx & IMX_RX_ERR)) {
			p->buf[p->wr++] = rx & 0xff;
			if (p->wr == sizeof(p->buf))
				p->wr = 0;
		}
	}

	wakeup(&p->wait_queue);
}

static void imx_disable(struct uart_port *p)
{
	/*
	 * Disable all
	 */
	iowrite32(0, p->membase + IMX_UCR1);
	iowrite32(0, p->membase + IMX_UCR2);
	iowrite32(0, p->membase + IMX_UCR3);
	iowrite32(0, p->membase + IMX_UCR4);
	iowrite32(0, p->membase + IMX_UFCR);

	irq_unregister(p->irq);
}

static void imx_setup(struct uart_port *p)
{
	int div = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&p->lock, flags);

	/*
	 * Disable all
	 */
	iowrite32(0, p->membase + IMX_UCR1);
	iowrite32(0, p->membase + IMX_UCR2);
	iowrite32(0, p->membase + IMX_UCR3);
	iowrite32(0, p->membase + IMX_UCR4);
	iowrite32(0, p->membase + IMX_UFCR);

	/*
	 * SW reset, no rts, TX enabled
	 * 8-bit data, 1-bit stop, none-parity
	 */
	iowrite32(IMX_UCR2_SRST | IMX_UCR2_IRTS | IMX_UCR2_TXEN |
		IMX_UCR2_WS | IMX_UCR2_STPB, p->membase + IMX_UCR2);

	/* Baud rate divisor
	 *	div = (UARTCLK / {16 * Baud rate})
	 */
	div = p->clk / (p->baudrate * p->divisor);
	div = max(min(div, 7), 1);
	iowrite32(IMX_UFCR_RFDIV(div), p->membase + IMX_UFCR);

	/* rx / tx trigger level */
	iowrite32(ioread32(p->membase + IMX_UFCR) |
		(8 << IMX_UFCR_TXTL_SHF) | 8, p->membase + IMX_UFCR);

	/*
	 * Enable UART without interrupt
	 */
	iowrite32(IMX_UCR1_UARTEN, p->membase + IMX_UCR1);

	spin_unlock_irqrestore(&p->lock, flags);
}

static void imx_attach(struct uart_port *p)
{
	imx_setup(p);

	p->irq = irq_of_register(p->dn, p->hwirq,
		(void *)imx_irq_handler, p);

	/*
	 * Enable RX and RX interrupt
	 */
 	iowrite32(ioread32(p->membase + IMX_UCR2) |
 			IMX_UCR2_RXEN, p->membase + IMX_UCR2);
	iowrite32(IMX_UCR4_OREN | IMX_UCR4_DREN, p->membase + IMX_UCR4);
}

static void imx_detach(struct uart_port *p)
{
	imx_disable(p);
}

static void imx_suspend(struct uart_port *p)
{
	imx_disable(p);
}

static void imx_resume(struct uart_port *p)
{
	imx_attach(p);
}

static const struct uart_ops imx_port_ops = {
	.tx = imx_puts,
	.rx = imx_gets,
	.suspend = imx_suspend,
	.resume = imx_resume,
	.attach = imx_attach,
	.detach = imx_detach,
};

static int __init imx_early_init(struct device_node *dn)
{
	struct uart_port *p = dev_get_drvdata(&dn->dev);

	imx_setup(p);

	p->ops = &imx_port_ops;

	return 0;
}
DECLARE_UART(imx, "imx,uart", imx_early_init);
