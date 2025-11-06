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
};

static void intc_soc_enable(struct irq_desc *d)
{
	struct intc_soc_desc *intc = d->controller->data;
	void *base = intc->base + INTC_SOC_ENABLE_REG;
	unsigned int bit = d->hwirq;

	if (bit < intc->max)
		iowrite32(ioread32(base) | (1 << bit), base);
}

static void intc_soc_disable(struct irq_desc *d)
{
	struct intc_soc_desc *intc = d->controller->data;
	void *base = intc->base + INTC_SOC_ENABLE_REG;
	unsigned int bit = d->hwirq;

	if (bit < intc->max)
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
	struct intc_soc_desc *intc = ic->data;
	unsigned long stat = ioread32(intc->base + INTC_SOC_STATUS_REG);

	for_each_set_bit(hwirq, &stat, intc->max) {
		irq_generic_invoke(ic, hwirq);
		iowrite32(BIT(hwirq), intc->base + INTC_SOC_STATUS_REG);
	}
}

static void __init intc_soc_init(struct device_node *dn)
{
	int ret = -1;
	struct intc_soc_desc *intc = NULL;
	struct irq_controller *ic = NULL;

	intc = kmalloc(sizeof(struct intc_soc_desc));
	if (intc == NULL)
		return;

	ret = of_irq_parse_max(dn, &intc->max);
	if (ret)
		return;

	intc->base = of_iomap(dn, 0);

	/* create an interrupt controller */
	ic = irq_create_controller(dn, intc->max, &__intc_soc_ops, intc);
	/* current controller's irq being chained to its parent controller */
	irq_chained_register(ic, 0, intc_soc_handler, ic);

	IMSG("%s irqs %d\n", dn->id.name, intc->max);
}
IRQ_CONTROLLER(ast2700_intc, "aspeed,ast2700-intc", intc_soc_init);
