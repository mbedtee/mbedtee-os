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
#define MIPS32_SOFTINT_SOURCE	(0)
#define MIPS32_INT_MASK			(0xFFul)
#define MIPS32_INT_SHIFT		(8)

static void mips_irq_disable(struct irq_desc *d)
{
	/*
	 * Disable Interrupt in Processor
	 */
	unsigned long stat = read_cp0_register(C0_STATUS);

	stat &= ~(1 << (d->hwirq + MIPS32_INT_SHIFT));

	write_cp0_register(C0_STATUS, stat);
}

static void mips_irq_enable(struct irq_desc *d)
{
	/*
	 * Enable Interrupt in Processor
	 */
	unsigned long stat = read_cp0_register(C0_STATUS);

	stat |= 1 << (d->hwirq + MIPS32_INT_SHIFT);

	write_cp0_register(C0_STATUS, stat);
}

/*
 * Send a softint (SGI) to the
 * processor specified by @cpu
 */
static void mips_softint_raise(struct irq_desc *d,
	unsigned int cpu)
{
	unsigned long cause = 0;

	if (d->hwirq != MIPS32_SOFTINT_SOURCE) {
		EMSG("wrong hwirq %d\n", d->hwirq);
		return;
	}

	cause = read_cp0_register(C0_CAUSE);

	cause |= 1 << (d->hwirq + MIPS32_INT_SHIFT);

	write_cp0_register(C0_CAUSE, cause);
}

static inline void mips_clear_softint(void)
{
	unsigned long cause = read_cp0_register(C0_CAUSE);

	cause &= ~(1 << (MIPS32_INT_SHIFT + MIPS32_SOFTINT_SOURCE));

	write_cp0_register(C0_CAUSE, cause);
}

static void mips_irq_handler(struct irq_controller *ic,
	struct thread_ctx *regs)
{
	int hwirq = 0;
	unsigned long val = regs->stat & regs->cause;

	val >>= MIPS32_INT_SHIFT;
	val &= MIPS32_INT_MASK;

	if (val & (1 << MIPS32_SOFTINT_SOURCE))
		mips_clear_softint();

	while (val != 0) {
		hwirq = __flsl(val);
		val &= ~(1ul << hwirq);
		irq_generic_invoke(ic, hwirq);
	}
}

static const struct irq_controller_ops mips_irq_ops = {
	.name = "mips32,intc",

	.irq_enable = mips_irq_enable,
	.irq_disable = mips_irq_disable,

	.irq_suspend = mips_irq_disable,
	.irq_resume = mips_irq_enable,

	.irq_send = mips_softint_raise,
};

/*
 * Initialize the MIPS32 interrupt controller
 */
static void __init mips32_intc_init(struct device_node *dn)
{
	struct irq_controller *ic = NULL;

	/* create interrupt controller, this is the root, no parent */
	ic = irq_create_percpu_controller(dn, 8, &mips_irq_ops, NULL);

	irq_set_root_handler(mips_irq_handler);

	/* MIPS32 provides one SGI for softint framework */
	softint_init(ic, &(unsigned int){MIPS32_SOFTINT_SOURCE}, 1);
}
IRQ_CONTROLLER(mips, "mips32,intc", mips32_intc_init);
