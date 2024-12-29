// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV Interrupt Controller
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

static struct riscv_intc_desc {
	bool sswi_exist;
	void *base;
	struct irq_controller *controller;
	struct irq_controller *softint_controller;
} riscv_desc = {0};

#define SWI_BASE ((uintptr_t)riscv_desc.base)

static void riscv_irq_disable(struct irq_desc *desc)
{
	clear_csr(CSR_IE, BIT(desc->hwirq));
}

static void riscv_irq_enable(struct irq_desc *desc)
{
	set_csr(CSR_IE, BIT(desc->hwirq));
}

static void riscv_irq_handler(struct thread_ctx *regs)
{
	unsigned int hwirq = regs->cause & LONG_MAX;

	irq_generic_invoke(riscv_desc.controller, hwirq);
}

/*
 * Send a softint (SGI) to the
 * processor specified by @cpu_id
 */
static void riscv_softint_raise(struct irq_desc *d,
	unsigned int cpu_id)
{
	unsigned long hartid = hartid_of(cpu_id);

	/*
	 * RPC calls to peer Execution Environment - todo
	 * here we get the first cpuid of peer REE, the CPUs mapping
	 * shall be (TEE CPUs | REE CPUs), TEE prior to REE
	 */
	if (d->hwirq == SOFTINT_RPC_CALLER)
		hartid = cpu_affinity_next_zero(cpus_online, 0);

	if (!IS_ENABLED(CONFIG_RISCV_S_MODE) || (riscv_desc.sswi_exist))
		iowrite32(1, (int *)SWI_BASE + hartid);
	else
		ecall(ECALL_SENDIPI, hartid, 0, SWI_BASE);
}

static void riscv_softint_handler(void *data)
{
	unsigned int id = 0;

	if (IS_ENABLED(CONFIG_RISCV_S_MODE))
		clear_csr(CSR_IP, BIT(RISCV_SOFTINT_SOURCE));
	else
		iowrite32(0, (int *)SWI_BASE + percpu_hartid());

	for (id = 0; id < RISCV_SOFTINT_MAX; id++)
		irq_generic_invoke(riscv_desc.softint_controller, id);
}

/*
 * Get the parent hwirq/handler of the specified #d
 */
static int riscv_softint_parent(struct irq_desc *d,
	unsigned int *hwirq, irq_handler_t *handler)
{
	if (!(d->controller->flags & IRQCTRL_SOFTINT))
		return -EINVAL;

	if (d->hwirq >= RISCV_SOFTINT_MAX)
		return -EINVAL;

	*hwirq = RISCV_SOFTINT_SOURCE;
	*handler = riscv_softint_handler;
	return 0;
}

static const struct irq_controller_ops riscv_irq_ops = {
	.name = "riscv,aclint",

	.irq_enable = riscv_irq_enable,
	.irq_disable = riscv_irq_disable,

	.irq_suspend = riscv_irq_disable,
	.irq_resume = riscv_irq_enable,
};

static const struct irq_controller_ops riscv_softint_ops = {
	.name = "riscv,aclint,softint",

	.irq_parent = riscv_softint_parent,

	.irq_send = riscv_softint_raise
};

/*
 * Initialize the basic RISCV interrupt controller
 */
static void __init riscv_intc_init(struct device_node *dn)
{
	size_t size = 0;
	unsigned long base = 0;
	int ret = -1, regidx = 0, forward = 0;
	struct riscv_intc_desc *d = &riscv_desc;

	regidx = IS_ENABLED(CONFIG_RISCV_S_MODE) ? 1 : 0;

	/* base register for Softint */
	ret = of_read_property_addr_size(dn, "reg", regidx, &base, &size);

	if (ret == 0) {
		d->base = iomap(base, size);
#if defined(CONFIG_RISCV_S_MODE)
		bool is_sswi_supported(void *sswi_base);
		d->sswi_exist = is_sswi_supported(d->base);
		forward = !d->sswi_exist;
#endif
	} else {
		forward = regidx;
	}

	/* get the mswi base for S-Mode forwarding the swi to M-Mode */
	if (forward) {
		of_read_property_addr_size(dn, "reg", 0,
			(unsigned long *)&d->base, NULL);
	}

	/* create interrupt controller, this is the root, no parent */
	d->controller = irq_create_percpu_controller(dn, 16, &riscv_irq_ops);

	/* create the Softint controller */
	d->softint_controller = irq_create_softint_controller(
			d->controller, RISCV_SOFTINT_MAX, &riscv_softint_ops);

	if (IS_ENABLED(CONFIG_RISCV_S_MODE))
		IMSG("sswi_exist: %d\n", d->sswi_exist);

	irq_set_root_handler(riscv_irq_handler);
}
IRQ_CONTROLLER(riscv, "riscv,aclint", riscv_intc_init);
