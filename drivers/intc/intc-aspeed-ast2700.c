// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * Join the ARM-GIC and AST2700 SoC's Interrupt-controller.
 */

#include <io.h>
#include <of.h>
#include <kmap.h>
#include <trace.h>
#include <kmalloc.h>

#include <interrupt.h>

#define INTC_SOC_ENABLE_REG	0x00
#define INTC_SOC_STATUS_REG	0x04

struct intc_soc_desc {
	void *base;
	unsigned int max;
	unsigned int parent_gic;
};

static void intc_soc_enable(struct irq_desc *d)
{
	struct intc_soc_desc *isd = d->controller->data;
	void *base = isd->base + INTC_SOC_ENABLE_REG;
	unsigned int bit = d->hwirq;

	if (bit < isd->max)
		iowrite32(ioread32(base) | (1 << bit), base);
}

static void intc_soc_disable(struct irq_desc *d)
{
	struct intc_soc_desc *isd = d->controller->data;
	void *base = isd->base + INTC_SOC_ENABLE_REG;
	unsigned int bit = d->hwirq;

	if (bit < isd->max)
		iowrite32(ioread32(base) & (~(1 << bit)), base);
}

static const struct irq_controller_ops __intc_soc_ops = {
	.name = "aspeed,ast2700-intc",

	.irq_enable	= intc_soc_enable,
	.irq_disable = intc_soc_disable,

	.irq_resume = intc_soc_enable,
	.irq_suspend = intc_soc_disable,
};

static void intc_soc_handler(void *data)
{
	uint32_t hwirq = 0;
	struct irq_controller *ic = data;
	struct intc_soc_desc *isd = ic->data;
	unsigned long stat = ioread32(isd->base + INTC_SOC_STATUS_REG);

	for_each_set_bit(hwirq, &stat, isd->max) {
		irq_generic_invoke(ic, hwirq);
		iowrite32(BIT(hwirq), isd->base + INTC_SOC_STATUS_REG);
	}
}

static void __init intc_soc_init(struct device_node *dn)
{
	int ret = -1;
	unsigned long base = 0;
	size_t size = 0;
	struct intc_soc_desc *d = NULL;
	struct irq_controller *ic = NULL;

	d = kmalloc(sizeof(struct intc_soc_desc));
	if (d == NULL) {
		EMSG("failed alloc for %s\n", dn->id.name);
		return;
	}

	ret = of_read_property_addr_size(dn, "reg", 0, &base, &size);
	if (ret != 0) {
		EMSG("error parsing %s\n", dn->id.name);
		return;
	}

	ret = of_property_read_u32(dn, "max-irqs", &d->max);
	if (ret)
		return;

	ret = of_property_read_u32(dn, "interrupts", &d->parent_gic);
	if (ret)
		return;

	d->base = iomap(base, size);

	/* create an interrupt controller */
	ic = irq_create_controller(dn, d->max, &__intc_soc_ops);
	/* link(register/enable) the irq @ its parent controller */
	irq_register(ic->parent, d->parent_gic, intc_soc_handler, ic);

	ic->data = d;

	IMSG("%s irqs %d\n", dn->id.name, d->max);
}
IRQ_CONTROLLER(ast2700_intc, "aspeed,ast2700-intc", intc_soc_init);
