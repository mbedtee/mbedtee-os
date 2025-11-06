// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Intel 8259 Interrupt Controller
 */

#include <io.h>
#include <of.h>
#include <kmap.h>
#include <trace.h>
#include <bitops.h>
#include <delay.h>

#include <interrupt.h>

static __volatile unsigned char master_irq_mask = 0xff;
static __volatile unsigned char slave_irq_mask = 0xff;

struct intc_desc {
	/* max interrupts in SoC */
	unsigned int max;

	struct spinlock lock;

	void *master;
	void *slave;
};

#define PIC_MASTER_CMD		(intc->master)
#define PIC_MASTER_IMR		(intc->master + 1)

#define PIC_SLAVE_CMD		(intc->slave)
#define PIC_SLAVE_IMR		(intc->slave + 1)

#define PIC_CASCADE_IR		2
#define MASTER_ICW4_DEFAULT	0x01
#define SLAVE_ICW4_DEFAULT	0x01
#define PIC_ICW4_AEOI		2

static void i8259_disable_irq(struct irq_desc *d)
{
	unsigned long flags = 0;
	struct intc_desc *intc = d->controller->data;

	spin_lock_irqsave(&intc->lock, flags);
	if (d->hwirq > 7) {
		slave_irq_mask |= (1 << (d->hwirq - 8));
		iowrite8(slave_irq_mask, PIC_SLAVE_IMR);
	} else {
		master_irq_mask |= (1 << d->hwirq);
		iowrite8(master_irq_mask, PIC_MASTER_IMR);
	}
	spin_unlock_irqrestore(&intc->lock, flags);
}

static void i8259_enable_irq(struct irq_desc *d)
{
	unsigned long flags = 0;
	struct intc_desc *intc = d->controller->data;

	spin_lock_irqsave(&intc->lock, flags);
	if (d->hwirq > 7) {
		slave_irq_mask &= ~(1 << (d->hwirq - 8));
		iowrite8(slave_irq_mask, PIC_SLAVE_IMR);
	} else {
		master_irq_mask &= ~(1 << d->hwirq);
		iowrite8(master_irq_mask, PIC_MASTER_IMR);
	}
	spin_unlock_irqrestore(&intc->lock, flags);
}

static inline int i8259_peek_irq(struct intc_desc *intc)
{
	int irq = -1;

	iowrite8(0x0C, PIC_MASTER_CMD);
	irq = ioread8(PIC_MASTER_CMD) & 7;
	if (irq == PIC_CASCADE_IR) {
		iowrite8(0x0C, PIC_SLAVE_CMD);
		irq = (ioread8(PIC_SLAVE_CMD) & 7) + 8;
	}

	return irq;
}

static void i8259_handler(void *data)
{
	struct irq_controller *ic = data;

	int hwirq = i8259_peek_irq(ic->data);

	if (hwirq < 0)
		return;

	irq_generic_invoke(ic, hwirq);
}

static void i8259_setup(struct intc_desc *intc)
{
	unsigned long flags;

	spin_lock_irqsave(&intc->lock, flags);

	iowrite8(0xff, PIC_MASTER_IMR); /* mask all of 8259A-1 */
	iowrite8(0xff, PIC_SLAVE_IMR); /* mask all of 8259A-2 */

	/*
	 * iowrite8 - this has to work on a wide range of PC hardware.
	 */
	iowrite8(0x11, PIC_MASTER_CMD); /* ICW1: select 8259A-1 init */
	iowrite8(0, PIC_MASTER_IMR); /* ICW2: 8259A-1 IR0 mapped to I8259A_IRQ_BASE + 0x00 */
	iowrite8(1U << PIC_CASCADE_IR, PIC_MASTER_IMR); /* 8259A-1 (the master) has a slave on IR2 */
	/* master expects normal EOI */
	iowrite8(MASTER_ICW4_DEFAULT | PIC_ICW4_AEOI, PIC_MASTER_IMR);

	iowrite8(0x11, PIC_SLAVE_CMD); /* ICW1: select 8259A-2 init */
	iowrite8(8, PIC_SLAVE_IMR);	/* ICW2: 8259A-2 IR0 mapped to I8259A_IRQ_BASE + 0x08 */
	iowrite8(PIC_CASCADE_IR, PIC_SLAVE_IMR); /* 8259A-2 is a slave on master's IR2 */
	/* (slave's support for AEOI in flat mode is to be investigated) */
	iowrite8(SLAVE_ICW4_DEFAULT | PIC_ICW4_AEOI, PIC_SLAVE_IMR);
	udelay(50);
	iowrite8(0xff, PIC_MASTER_IMR);	/* mask all of 8259A-1 */
	iowrite8(0xff, PIC_SLAVE_IMR);	/* mask all of 8259A-2 */

	spin_unlock_irqrestore(&intc->lock, flags);
}

static void i8259_resume(struct irq_controller *ic)
{
	i8259_setup(ic->data);
}

static const struct irq_controller_ops i8259_ops = {
	.name = "intel,i8259",

	.irq_enable = i8259_enable_irq,
	.irq_disable = i8259_disable_irq,

	.irq_resume = i8259_enable_irq,
	.irq_suspend = i8259_disable_irq,

	.irq_controller_resume = i8259_resume,
};

static void __init i8259_init(struct device_node *dn)
{
	int ret = -1;
	struct intc_desc *intc = NULL;
	struct irq_controller *ic = NULL;

	intc = kmalloc(sizeof(*intc));
	if (intc == NULL)
		return;

	intc->master = of_iomap(dn, 0);
	intc->slave = of_iomap(dn, 1);

	ret = of_irq_parse_max(dn, &intc->max);
	if (ret)
		return;

	i8259_setup(intc);

	/* create an interrupt controller, link it with its parent controller */
	ic = irq_create_controller(dn, intc->max, &i8259_ops, intc);
	/* current controller's irq being chained to its parent controller */
	irq_chained_register(ic, 0, i8259_handler, ic);
}
IRQ_CONTROLLER(i8259, "intel,i8259", i8259_init);
