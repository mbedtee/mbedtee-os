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

struct intc_soc_desc {
	/* max interrupts in SoC */
	unsigned int max;

	/* Interrupt Controller enable_regs in SoC */
	uint32_t *enable_regs;
	/* Interrupt Controller stat_regs in SoC */
	uint32_t *stat_regs;
};

#define REG_INDEX(n) ((n) >> BIT_SHIFT_PER_INT)
#define BIT_OFFSET(n) BIT((n) & BIT_MASK_PER_INT)

static void intc_soc_enable(struct irq_desc *d)
{
	struct intc_soc_desc *intc = d->controller->data;
	uint32_t *reg = intc->enable_regs + REG_INDEX(d->hwirq);

	iowrite32(ioread32(reg) | BIT_OFFSET(d->hwirq), reg);
}

static void intc_soc_disable(struct irq_desc *d)
{
	struct intc_soc_desc *intc = d->controller->data;
	uint32_t *reg = intc->enable_regs + REG_INDEX(d->hwirq);

	iowrite32(ioread32(reg) & ~BIT_OFFSET(d->hwirq), reg);
}

static void intc_soc_handler(void *data)
{
	struct irq_controller *ic = data;
	struct intc_soc_desc *intc = ic->data;
	uint32_t i = 0, pending = 0, hwirq = 0;

	for (i = 0; i < (intc->max >> BIT_SHIFT_PER_INT); i++) {
		pending = ioread32(intc->stat_regs + i) &
				ioread32(intc->enable_regs + i);
		if (pending) {
			hwirq = (i << BIT_SHIFT_PER_INT) + __fls(pending);
			irq_generic_invoke(ic, hwirq);
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
	struct intc_soc_desc *intc = NULL;
	struct irq_controller *ic = NULL;

	intc = kmalloc(sizeof(*intc));
	if (intc == NULL)
		return;

	intc->enable_regs = of_iomap(dn, 0);
	if (intc->enable_regs)
		return;

	intc->stat_regs = of_iomap(dn, 1);
	if (intc->stat_regs)
		return;

	ret = of_irq_parse_max(dn, &intc->max);
	if (ret)
		return;

	intc_soc_disable_all(intc);

	/* create an interrupt controller, link it with its parent controller */
	ic = irq_create_controller(dn, intc->max, &__intc_soc_ops, intc);
	/* current controller's irq being chained to its parent controller */
	irq_chained_register(ic, 0, intc_soc_handler, ic);
}
IRQ_CONTROLLER(salix, "salix,intc", intc_soc_init);
