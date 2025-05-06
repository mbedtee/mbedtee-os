// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * PLIC Interrupt-controller
 */

#include <io.h>
#include <of.h>
#include <kmap.h>
#include <trace.h>
#include <bitops.h>

#include <interrupt.h>

#define PRIORITY_BASE			0x000000
#define CONTEXT_BASE			0x200000
#define CONTEXT_ENABLE_BASE		0x002000

#define CONTEXT_SIZE			0x1000
#define	CONTEXT_ENABLE_SIZE		0x0080

#define CONTEXT_THRESHOLD		0x00
#define CONTEXT_CLAIM			0x04

#define PLIC_REG_OFFSET(n) (BYTES_PER_INT * ((n) / BITS_PER_INT))
#define PLIC_BIT_OFFSET(n) ((n) % BITS_PER_INT)

struct plic_desc {
	/* max interrupts in PLIC */
	unsigned int max;

	/* memory-mapped registers */
	void *regs;
};

static void plic_percpu_init(void);

static void plic_set_enable(void *enreg, int irq)
{
	uint32_t *reg = enreg + PLIC_REG_OFFSET(irq);
	uint32_t mask = BIT(PLIC_BIT_OFFSET(irq));

	iowrite32(ioread32(reg) | mask, reg);
}

static void plic_clear_enable(void *enreg, int irq)
{
	uint32_t *reg = enreg + PLIC_REG_OFFSET(irq);
	uint32_t mask = BIT(PLIC_BIT_OFFSET(irq));

	iowrite32(ioread32(reg) & ~mask, reg);
}

static void *plic_enable_base(struct plic_desc *d, int hartid)
{
	int i = 0;
	void *regs = d->regs + CONTEXT_ENABLE_BASE;

	while (i < hartid) {
		regs += CONTEXT_ENABLE_SIZE;
		if (supervisor_bmap() & (1 << i))
			regs += CONTEXT_ENABLE_SIZE;
		i++;
	}

	if (IS_ENABLED(CONFIG_RISCV_S_MODE))
		regs += CONTEXT_ENABLE_SIZE;

	return regs;
}

static void *plic_context_base(struct plic_desc *d, int hartid)
{
	int i = 0;
	void *regs = d->regs + CONTEXT_BASE;

	while (i < hartid) {
		regs += CONTEXT_SIZE;
		if (supervisor_bmap() & (1 << i))
			regs += CONTEXT_SIZE;
		i++;
	}

	if (IS_ENABLED(CONFIG_RISCV_S_MODE))
		regs += CONTEXT_SIZE;

	return regs;
}

static void plic_irq_enable(struct irq_desc *d)
{
	unsigned int cpu = 0;
	unsigned int hartid = 0;
	struct plic_desc *plic = d->controller->data;

	for_each_affinity_cpu(cpu, d->affinity) {
		hartid = hartid_of(cpu);
		plic_set_enable(plic_enable_base(plic, hartid), d->hwirq);
	}
}

static void plic_irq_disable(struct irq_desc *d)
{
	unsigned int cpu = 0;
	unsigned int hartid = 0;
	struct plic_desc *plic = d->controller->data;

	for_each_affinity_cpu(cpu, d->affinity) {
		hartid = hartid_of(cpu);
		plic_clear_enable(plic_enable_base(plic, hartid), d->hwirq);
	}
}

static void plic_irq_handler(void *data)
{
	unsigned int irq = 0;
	unsigned int hartid = percpu_hartid();
	struct irq_controller *ic = data;
	struct plic_desc *plic = ic->data;
	void *claim = plic_context_base(plic, hartid) + CONTEXT_CLAIM;

	while ((irq = ioread32(claim)) != 0) {
		irq_generic_invoke(ic, irq);
		iowrite32(irq, claim); /* EOI */
	}
}

static int plic_set_affinity(struct irq_desc *d,
	const struct cpu_affinity *affinity, bool force)
{
	unsigned int cpu = -1;
	struct cpu_affinity tmp;

	if (force) {
		if (cpu_affinity_isset(affinity, percpu_id()))
			cpu = percpu_id();
		else
			cpu = cpu_affinity_next_one(affinity, 0);
	} else {
		cpu_affinity_and(&tmp, affinity, cpus_online);
		cpu = cpu_affinity_next_one(&tmp, 0);
	}

	if (!cpu_affinity_valid(cpu))
		return -EINVAL;

	plic_irq_disable(d);

	cpu_affinity_copy(d->affinity, affinity);

	if (irq_is_enabled(d))
		plic_irq_enable(d);

	return 0;
}

static void plic_setup(struct plic_desc *d)
{
	int i = 0, hartid = 0, irq = 0;
	void *enreg = NULL, *ctxreg = NULL;

	for_each_possible_cpu(i) {
		hartid = hartid_of(i);

		enreg = plic_enable_base(d, hartid);
		ctxreg = plic_context_base(d, hartid);

		/* clear M-Mode */
		for (irq = 1; irq < d->max; irq++)
			plic_clear_enable(enreg, irq);

		/* permits all external interrupts */
		iowrite32(0, ctxreg + CONTEXT_THRESHOLD);

		/* clear S-Mode */
		enreg += CONTEXT_ENABLE_SIZE;
		for (irq = 1; irq < d->max; irq++)
			plic_clear_enable(enreg, irq);

		/* permits all external interrupts */
		ctxreg += CONTEXT_SIZE;
		iowrite32(0, ctxreg + CONTEXT_THRESHOLD);
	}

	/* priority of all external interrupts is 1 (lowest) */
	for (irq = 0; irq < d->max; irq++)
		iowrite32(1, d->regs + PRIORITY_BASE + irq * 4);
}

static void plic_resume(struct irq_controller *ic)
{
	plic_setup(ic->data);
	plic_percpu_init();
}

static const struct irq_controller_ops plic_intc_ops = {
	.name = "riscv,plic",
	.irq_enable	= plic_irq_enable,
	.irq_disable = plic_irq_disable,
	.irq_set_affinity = plic_set_affinity,

	.irq_controller_resume = plic_resume
};

static int __init plic_parse_dts(struct plic_desc *d,
	struct device_node *dn)
{
	int ret = -1;

	d->regs = of_iomap(dn, 0);
	if (d->regs == NULL)
		return -EINVAL;

	ret = of_irq_parse_max(dn, &d->max);
	if (ret)
		return -EINVAL;

	IMSG("init %s %d irqs\n", dn->id.name, d->max);
	return 0;
}

static void plic_percpu_init(void)
{
	struct irq_controller *ic = NULL;

	/*
	 * currently there is only one plic in one RISCV system.
	 * if there are multi-plic in one RISCV system in the future,
	 * add a irq_for_each_matching_controller() to handle them all.
	 */
	ic = irq_matching_ops_controller(&plic_intc_ops);

	/* percpu plic chained to its parent controller */
	irq_chained_register(ic, IS_ENABLED(CONFIG_RISCV_S_MODE), plic_irq_handler, ic);
}
PERCPU_INIT_ROOT(plic_percpu_init);

static void __init plic_intc_init(struct device_node *dn)
{
	struct plic_desc *d = NULL;

	d = kmalloc(sizeof(*d));
	if (d == NULL)
		return;

	if (plic_parse_dts(d, dn) != 0)
		return;

	plic_setup(d);

	/*
	 * create an interrupt controller, it also will be chained to its
	 * parent controller later at percpu routine -> plic_percpu_init()
	 */
	irq_create_controller(dn, d->max, &plic_intc_ops, d);
}
IRQ_CONTROLLER(plic, "riscv,plic", plic_intc_init);
