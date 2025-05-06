// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV aclint Interrupt Controller
 */

#include <io.h>
#include <of.h>
#include <cpu.h>
#include <ipi.h>
#include <defs.h>
#include <kmap.h>
#include <trace.h>
#include <sched.h>
#include <driver.h>
#include <bitops.h>
#include <kmalloc.h>
#include <interrupt.h>

/*
 * Software Generated Interrupt (SGI)
 * For RISCV, Softint source is 1 or 3
 */
#define RISCV_SOFTINT_SOURCE (IS_ENABLED(CONFIG_RISCV_S_MODE) ? 1 : 3)

#define RISCV_SOFTINT_MAX SOFTINT_MAX

struct riscv_desc {
	bool sswi_exist;
	void *base;
};

static void riscv_irq_disable(struct irq_desc *desc)
{
	clear_csr(CSR_IE, BIT(desc->hwirq));
}

static void riscv_irq_enable(struct irq_desc *desc)
{
	set_csr(CSR_IE, BIT(desc->hwirq));
}

static void riscv_irq_handler(struct irq_controller *ic,
	struct thread_ctx *regs)
{
	unsigned int hwirq = regs->cause & LONG_MAX;

	/* clear the softint */
	if (hwirq == RISCV_SOFTINT_SOURCE) {
		struct riscv_desc *intc = ic->data;

		if (IS_ENABLED(CONFIG_RISCV_S_MODE))
			clear_csr(CSR_IP, BIT(RISCV_SOFTINT_SOURCE));
		else
			iowrite32(0, (int *)intc->base + percpu_hartid());
	}

	irq_generic_invoke(ic, hwirq);
}

/*
 * Send a softint (SGI) to the
 * processor specified by @cpu
 */
static void riscv_softint_raise(struct irq_desc *d,
	unsigned int cpu)
{
	unsigned long hartid = 0;
	struct riscv_desc *intc = d->controller->data;

	hartid = VALID_CPUID(cpu) ? hartid_of(cpu) : cpu;

	if (!IS_ENABLED(CONFIG_RISCV_S_MODE) || (intc->sswi_exist))
		iowrite32(1, (int *)intc->base + hartid);
	else
		ecall(ECALL_SENDIPI, hartid, 0, (long)intc->base);
}

static const struct irq_controller_ops riscv_irq_ops = {
	.name = "riscv,aclint",

	.irq_enable = riscv_irq_enable,
	.irq_disable = riscv_irq_disable,

	.irq_suspend = riscv_irq_disable,
	.irq_resume = riscv_irq_enable,

	.irq_send = riscv_softint_raise,
};

/*
 * Initialize the basic RISCV aclint interrupt controller
 */
static void __init riscv_intc_init(struct device_node *dn)
{
	int regidx = 0, forward = 0;
	struct riscv_desc *d = NULL;
	struct irq_controller *ic = NULL;

	d = kmalloc(sizeof(*d));
	if (d == NULL)
		return;

	regidx = IS_ENABLED(CONFIG_RISCV_S_MODE) ? 1 : 0;

	/* base register for Softint */
	d->base = of_iomap(dn, regidx);
	if (d->base) {
#if defined(CONFIG_RISCV_S_MODE)
		d->sswi_exist = is_io_readable(d->base);
		forward = !d->sswi_exist;
		if (forward)
			iounmap(d->base);
#endif
	} else {
		forward = regidx;
	}

	if (IS_ENABLED(CONFIG_RISCV_S_MODE))
		IMSG("sswi_exist: %d\n", d->sswi_exist);

	/* get the mswi base for S-Mode forwarding the swi to M-Mode */
	if (forward)
		of_parse_io_resource(dn, 0, (unsigned long *)&d->base, NULL);

	/* create interrupt controller, this is the root, no parent */
	ic = irq_create_percpu_controller(dn, 16, &riscv_irq_ops, d);

	irq_set_root_handler(riscv_irq_handler);

	/*
	 * provides one SGI source for softint framework
	 * if the imsic present, imsic provides the SGI instead clint.
	 */
	if (!of_find_compatible_node(NULL, "riscv,imsic"))
		softint_init(ic, &(unsigned int){RISCV_SOFTINT_SOURCE}, 1);
}
IRQ_CONTROLLER(riscv, "riscv,aclint", riscv_intc_init);
