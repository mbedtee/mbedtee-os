// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Salix MIPS SoC's Interrupt-controller.
 */

#include <io.h>
#include <of.h>
#include <kmap.h>
#include <trace.h>
#include <bitops.h>

#include <interrupt.h>

static struct intc_soc_desc {
	/* max interrupts in SoC */
	unsigned int max;

	/*
	 * interrupt index connected to its parent Processor
	 * e.g. connected to MIPS -> IP2 ~ 7 ?
	 */
	unsigned int hwirq;

	/* Interrupt Controller enable_regs in SoC */
	uint32_t *enable_regs;
	/* Interrupt Controller stat_regs in SoC */
	uint32_t *stat_regs;

	struct irq_controller *controller;
} intc_soc = {0};

#define REG_INDEX(n) ((n) >> BIT_SHIFT_PER_INT)
#define BIT_OFFSET(n) BIT((n) & BIT_MASK_PER_INT)

static void intc_soc_enable(struct irq_desc *desc)
{
	uint32_t *reg = intc_soc.enable_regs + REG_INDEX(desc->hwirq);

	iowrite32(ioread32(reg) | BIT_OFFSET(desc->hwirq), reg);
}

static void intc_soc_disable(struct irq_desc *desc)
{
	uint32_t *reg = intc_soc.enable_regs + REG_INDEX(desc->hwirq);

	iowrite32(ioread32(reg) & ~BIT_OFFSET(desc->hwirq), reg);
}

static void intc_soc_handler(void *data)
{
	struct intc_soc_desc *d = data;
	uint32_t i = 0, pending = 0, hwirq = 0;

	for (i = 0; i < (d->max >> BIT_SHIFT_PER_INT); i++) {
		pending = ioread32(d->stat_regs + i) &
				ioread32(d->enable_regs + i);
		if (pending) {
			hwirq = (i << BIT_SHIFT_PER_INT) + __fls(pending);
			irq_generic_invoke(d->controller, hwirq);
		}
	}
}

static void intc_soc_disable_all(struct intc_soc_desc *d)
{
	int i = 0;

	for (i = 0; i < (d->max >> BIT_SHIFT_PER_INT); i++)
		iowrite32(0, d->enable_regs + i);
}

static const struct irq_controller_ops __intc_soc_ops = {
	.name = "salix,intc",

	.irq_enable	= intc_soc_enable,
	.irq_disable = intc_soc_disable,
};

static void __init intc_soc_init(struct device_node *dn)
{
	int ret = -1;
	unsigned long addr = 0;
	size_t size = 0;
	struct intc_soc_desc *d = &intc_soc;
	struct irq_controller *ic = NULL;

	ret = of_read_property_addr_size(dn, "reg", 0, &addr, &size);
	if (ret)
		return;
	d->enable_regs = iomap(addr, size);

	ret = of_read_property_addr_size(dn, "reg", 1, &addr, &size);
	if (ret)
		return;
	d->stat_regs = iomap(addr, size);

	ret = of_property_read_u32(dn, "interrupts", &d->hwirq);
	if (ret)
		return;

	ret = of_property_read_u32(dn, "max-irqs", &d->max);
	if (ret)
		return;

	/* create an interrupt controller, link it with its parent controller */
	ic = irq_create_controller(dn, d->max, &__intc_soc_ops);
	/* link(register/enable) the irq @ its parent controller */
	irq_register(ic->parent, d->hwirq, intc_soc_handler, d);

	d->controller = ic;

	intc_soc_disable_all(d);
}
IRQ_CONTROLLER(salix, "salix,intc", intc_soc_init);
