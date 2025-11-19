// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * xilinx XPS Interrupt-controller.
 */

#include <io.h>
#include <of.h>
#include <kmap.h>
#include <trace.h>
#include <bitops.h>

#include <interrupt.h>

#define R_ISR       (0 << 2)
#define R_IPR       (1 << 2)
#define R_IER       (2 << 2)
#define R_IAR       (3 << 2)
#define R_SIE       (4 << 2)
#define R_CIE       (5 << 2)
#define R_IVR       (6 << 2)
#define R_MER       (7 << 2)

struct xlnx_intc_desc {
	/* max interrupts in SoC */
	unsigned int max;

	/* Interrupt Controller registers */
	void *base;
};

static void xlnx_intc_enable(struct irq_desc *d)
{
	struct xlnx_intc_desc *intc = d->controller->data;

	iowrite32(BIT(d->hwirq), intc->base + R_SIE);
}

static void xlnx_intc_disable(struct irq_desc *d)
{
	struct xlnx_intc_desc *intc = d->controller->data;

	iowrite32(BIT(d->hwirq), intc->base + R_CIE);
}

static void xlnx_intc_handler(void *data)
{
	uint32_t hwirq = 0;
	struct irq_controller *ic = data;
	struct xlnx_intc_desc *intc = ic->data;

	while ((hwirq = ioread32(intc->base + R_IVR)) < intc->max) {
		iowrite32(BIT(hwirq), intc->base + R_IAR);
		irq_generic_invoke(ic, hwirq);
	}
}

static void xlnx_intc_setup(struct xlnx_intc_desc *intc)
{
	/*
	 * Disable all
	 */
	iowrite32(0, intc->base + R_IER);

	/* Acknowledge all */
	iowrite32(0xffffffff, intc->base + R_IAR);

	/* Turn on the Master Enable. */
	iowrite32(3, intc->base + R_MER);
}

static const struct irq_controller_ops __xlnx_intc_ops = {
	.name = "xlnx,xps-intc",

	.irq_enable	= xlnx_intc_enable,
	.irq_disable = xlnx_intc_disable,
};

static void __init xlnx_intc_init(struct device_node *dn)
{
	int ret = -1;
	struct xlnx_intc_desc *intc = NULL;
	struct irq_controller *ic = NULL;

	intc = kmalloc(sizeof(*intc));
	if (intc == NULL)
		return;

	intc->base = of_iomap(dn, 0);
	if (!intc->base)
		return;

	ret = of_irq_parse_max(dn, &intc->max);
	if (ret)
		return;

	xlnx_intc_setup(intc);

	/* create an interrupt controller, link it with its parent controller */
	ic = irq_create_controller(dn, intc->max, &__xlnx_intc_ops, intc);
	/* current controller's irq being chained to its parent controller */
	irq_chained_register(ic, IS_ENABLED(CONFIG_RISCV_S_MODE), xlnx_intc_handler, ic);

	IMSG("%s irqs %d\n", dn->id.name, intc->max);
}
IRQ_CONTROLLER(xlnx_xps, "xlnx,xps-intc", xlnx_intc_init);
