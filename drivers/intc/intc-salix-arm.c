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

static struct intc_soc_desc {
	void *base;
	unsigned int max;
	unsigned int *gics;
	struct irq_controller *controller;
} intc_soc_desc = {0};

static void intc_soc_enable(struct irq_desc *d)
{
	void *base = 0;
	unsigned int bit = 0;

	base = (void *)((sizeof(int) * (d->hwirq/BITS_PER_INT))
			+ intc_soc_desc.base);
	bit = (d->hwirq % BITS_PER_INT);

	iowrite32(ioread32(base) | (1 << bit), base);
}

static void intc_soc_disable(struct irq_desc *d)
{
	void *base = 0;
	unsigned int bit = 0;

	base = (void *)((sizeof(long) * (d->hwirq/BITS_PER_INT))
			+ intc_soc_desc.base);
	bit = (d->hwirq % BITS_PER_INT);

	iowrite32(ioread32(base) & (~(1 << bit)), base);
}

static int intc_soc_parent(struct irq_desc *d,
	unsigned int *hwirq, irq_handler_t *handler)
{
	int gic_num = 0;

	/* get the soc interrupt's parent @ gic */
	gic_num = intc_soc_desc.gics[d->hwirq];
	if (gic_num == 0)
		return -EINVAL;

	*hwirq = gic_num + 32; /* add the SPI base */

	return 0;
}

static const struct irq_controller_ops __intc_soc_ops = {
	.irq_enable	= intc_soc_enable,
	.irq_disable = intc_soc_disable,
	.irq_parent = intc_soc_parent,
};

static void __init intc_soc_init(struct device_node *dn)
{
	int ret = -1;
	unsigned long base = 0;
	size_t size = 0;
	struct intc_soc_desc *d = &intc_soc_desc;

	ret = of_read_property_addr_size(dn, "reg", 0, &base, &size);
	if (ret != 0) {
		IMSG("error parsing %s\n", dn->id.name);
		return;
	}

	ret = of_property_read_u32(dn, "max-irqs", &d->max);
	if (ret)
		return;

	d->gics = kcalloc(d->max, sizeof(unsigned int));
	if (!d->gics)
		return;

	ret = of_property_read_u32_array(dn, "gic-table", d->gics, d->max);
	if (ret < 0) {
		EMSG("error read gic-table @ %s\n", dn->id.name);
		kfree(d->gics);
		return;
	}

	d->base = iomap(base, size);

	/* create an interrupt controller */
	d->controller = irq_create_controller(dn, d->max, &__intc_soc_ops);

	IMSG("%s irqs %d\n", dn->id.name, d->max);
}
IRQ_CONTROLLER(salix, "salix,intc", intc_soc_init);
