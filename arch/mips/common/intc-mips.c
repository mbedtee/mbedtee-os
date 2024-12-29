// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 Interrupt Controller
 */

#include <io.h>
#include <of.h>
#include <ipi.h>
#include <defs.h>
#include <kmap.h>
#include <trace.h>
#include <driver.h>
#include <bitops.h>

#include <interrupt.h>

#include <generated/autoconf.h>

/*
 * Software Generated Interrupt
 * For MIPS32, SGI source is 0 or 1
 */
#define MIPS32_SOFTINT_SOURCE (0)
#define MIPS32_SOFTINT_MAX SOFTINT_MAX

#define MIPS32_PRIV_INT(x) ((x) < 8)

#define MIPS32_INT_MASK		(0xFFul)
#define MIPS32_INT_SHIFT	(8)

static struct mips_intc_desc {
	struct irq_controller *controller;
	struct irq_controller *softint_controller;
} mips_desc = {0};

static void mips_irq_disable(struct irq_desc *desc)
{
	/*
	 * Disable Interrupt in Processor
	 */
	unsigned long stat = read_cp0_register(C0_STATUS);

	stat &= ~(1 << (desc->hwirq + MIPS32_INT_SHIFT));

	write_cp0_register(C0_STATUS, stat);
}

static void mips_irq_enable(struct irq_desc *desc)
{
	/*
	 * Enable Interrupt in Processor
	 */
	unsigned long stat = read_cp0_register(C0_STATUS);

	stat |= 1 << (desc->hwirq + MIPS32_INT_SHIFT);

	write_cp0_register(C0_STATUS, stat);
}

/*
 * Send a softint (SGI) to the
 * processor specified by @cpu_id
 * (#cpu_id, due to currently only one core for mips)
 */
static void mips_softint_raise(struct irq_desc *d,
	unsigned int cpu_id)
{
	unsigned long cause = 0;

	cause = read_cp0_register(C0_CAUSE);

	cause |= 1 << (MIPS32_INT_SHIFT + MIPS32_SOFTINT_SOURCE);

	write_cp0_register(C0_CAUSE, cause);
}

static void mips_irq_handler(struct thread_ctx *regs)
{
	int hwirq = 0;
	unsigned long val = regs->stat & regs->cause;

	val >>= MIPS32_INT_SHIFT;
	val &= MIPS32_INT_MASK;

	while (val != 0) {
		hwirq = __flsl(val);
		val &= ~(1ul << hwirq);
		irq_generic_invoke(mips_desc.controller, hwirq);
	}
}

static void mips_softint_handler(void *data)
{
	unsigned int id = 0;
	unsigned long cause = read_cp0_register(C0_CAUSE);

	cause &= ~(1 << (MIPS32_INT_SHIFT + MIPS32_SOFTINT_SOURCE));

	write_cp0_register(C0_CAUSE, cause);

	for (id = 0; id < MIPS32_SOFTINT_MAX; id++)
		irq_generic_invoke(mips_desc.softint_controller, id);
}

/*
 * Get the parent hwirq/handler of the specified #d
 */
static int mips_softint_parent(struct irq_desc *d, unsigned int *hwirq,
	irq_handler_t *handler)
{
	if (!(d->controller->flags & IRQCTRL_SOFTINT))
		return -EINVAL;

	if (d->hwirq >= MIPS32_SOFTINT_MAX)
		return -EINVAL;

	*hwirq = MIPS32_SOFTINT_SOURCE;
	*handler = mips_softint_handler;
	return 0;
}

static const struct irq_controller_ops mips_irq_ops = {
	.name = "mips32,intc",

	.irq_enable = mips_irq_enable,
	.irq_disable = mips_irq_disable,

	.irq_suspend = mips_irq_disable,
	.irq_resume = mips_irq_enable,
};

static const struct irq_controller_ops mips_softint_ops = {
	.name = "mips32,softint",

	.irq_parent = mips_softint_parent,
	.irq_send = mips_softint_raise
};

/*
 * Initialize the MIPS32 interrupt controller
 */
static void __init mips32_intc_init(struct device_node *dn)
{
	struct mips_intc_desc *d = &mips_desc;

	/* create interrupt controller, this is the root, no parent */
	d->controller = irq_create_percpu_controller(dn, 8, &mips_irq_ops);

	/* create the Softint controller */
	d->softint_controller = irq_create_softint_controller(
			d->controller, MIPS32_SOFTINT_MAX, &mips_softint_ops);

	irq_set_root_handler(mips_irq_handler);
}
IRQ_CONTROLLER(mips, "mips32,intc", mips32_intc_init);
