// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Join the ARM-GIC and SoC's Interrupt-controller.
 */

#include <io.h>
#include <of.h>
#include <kmap.h>
#include <trace.h>
#include <kmalloc.h>

#include <interrupt.h>

struct intc_soc_desc {
	void *base;
	unsigned int max;
	unsigned int *gics;
};

static void intc_soc_enable(struct irq_desc *d)
{
	void *base = 0;
	unsigned int bit = 0;
	struct intc_soc_desc *intc = d->controller->data;

	base = intc->base + (sizeof(int) * (d->hwirq / BITS_PER_INT));
	bit = d->hwirq % BITS_PER_INT;

	iowrite32(ioread32(base) | (1 << bit), base);
}

static void intc_soc_disable(struct irq_desc *d)
{
	void *base = 0;
	unsigned int bit = 0;
	struct intc_soc_desc *intc = d->controller->data;

	base = intc->base + (sizeof(int) * (d->hwirq / BITS_PER_INT));
	bit = d->hwirq % BITS_PER_INT;

	iowrite32(ioread32(base) & (~(1 << bit)), base);
}

static int intc_soc_translate(struct irq_desc *d,
	unsigned int *hwirq, unsigned int *type)
{
	int gic_num = 0;
	struct intc_soc_desc *intc = d->controller->data;

	if (d->hwirq >= intc->max)
		return -EINVAL;

	/* get the soc interrupt's parent @ gic */
	gic_num = intc->gics[d->hwirq];
	if (gic_num == 0)
		return -EINVAL;

	/* add the SPI base */
	*hwirq = gic_num + 32;
	*type = 0;

	return 0;
}

static const struct irq_controller_ops __intc_soc_ops = {
	.irq_enable	= intc_soc_enable,
	.irq_disable = intc_soc_disable,
	.irq_translate = intc_soc_translate,
};

static void __init intc_soc_init(struct device_node *dn)
{
	int ret = -1;
	struct intc_soc_desc *intc = NULL;

	intc = kmalloc(sizeof(*intc));
	if (intc == NULL)
		return;

	ret = of_irq_parse_max(dn, &intc->max);
	if (ret)
		return;

	intc->gics = kcalloc(intc->max, sizeof(unsigned int));
	if (!intc->gics)
		return;

	ret = of_property_read_u32_array(dn, "gic-table", intc->gics, intc->max);
	if (ret < 0) {
		EMSG("error read gic-table @ %s\n", dn->id.name);
		kfree(intc->gics);
		return;
	}

	intc->base = of_iomap(dn, 0);
	if (!intc->base) {
		kfree(intc->gics);
		return;
	}

	/* create an interrupt controller */
	irq_create_controller(dn, intc->max, &__intc_soc_ops, intc);

	IMSG("%s irqs %d\n", dn->id.name, intc->max);
}
IRQ_CONTROLLER(salix, "salix,intc", intc_soc_init);
