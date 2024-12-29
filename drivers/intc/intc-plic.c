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

static struct plic_intc_desc {
	/* max interrupts in PLIC */
	unsigned int max;

	/*
	 * interrupt index connected to its parent Processor
	 * e.g. connected to RISCV CPU -> IP11 or IP9 ?
	 */
	unsigned int hwirq;

	/* hart0 does not have supervisor mode ? */
	unsigned int hart0_supervisor_supported;

	struct device_node *dn;

	struct irq_controller *controller;

	/* memory-mapped registers */
	void *regs;
} plic_desc = {0};

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

static void *plic_enable_base(int hartid)
{
	void *regs = NULL;

	regs = plic_desc.regs + CONTEXT_ENABLE_BASE +
			(hartid * 2) * CONTEXT_ENABLE_SIZE;

	if (hartid && !plic_desc.hart0_supervisor_supported)
		regs -= CONTEXT_ENABLE_SIZE;

	if (IS_ENABLED(CONFIG_RISCV_S_MODE))
		if (hartid || plic_desc.hart0_supervisor_supported)
			regs += CONTEXT_ENABLE_SIZE;

	return regs;
}

static void *plic_conetxt_base(int hartid)
{
	void *regs = NULL;

	regs = plic_desc.regs + CONTEXT_BASE +
			(hartid * 2) * CONTEXT_SIZE;

	if (hartid && !plic_desc.hart0_supervisor_supported)
		regs -= CONTEXT_SIZE;

	if (IS_ENABLED(CONFIG_RISCV_S_MODE))
		if (hartid || plic_desc.hart0_supervisor_supported)
			regs += CONTEXT_SIZE;

	return regs;
}

static void plic_irq_enable(struct irq_desc *desc)
{
	unsigned int cpu = 0;
	unsigned int hartid = 0;

	for_each_affinity_cpu(cpu, desc->affinity) {
		hartid = hartid_of(cpu);
		plic_set_enable(plic_enable_base(hartid), desc->hwirq);
	}
}

static void plic_irq_disable(struct irq_desc *desc)
{
	unsigned int cpu = 0;
	unsigned int hartid = 0;

	for_each_affinity_cpu(cpu, desc->affinity) {
		hartid = hartid_of(cpu);
		plic_clear_enable(plic_enable_base(hartid), desc->hwirq);
	}
}

static void plic_irq_handler(void *data)
{
	unsigned int irq = 0;
	unsigned int hartid = percpu_hartid();
	void *claim = plic_conetxt_base(hartid) + CONTEXT_CLAIM;

	while ((irq = ioread32(claim)) != 0) {
		irq_generic_invoke(data, irq);
		iowrite32(irq, claim); /* EOI */
	}
}

static int plic_set_affinity(struct irq_desc *desc,
	const struct cpu_affinity *affinity)
{
	unsigned int cpu;
	struct cpu_affinity tmp;

	cpu_affinity_and(&tmp, affinity, cpus_online);

	cpu = cpu_affinity_next_one(&tmp, 0);
	if (!cpu_affinity_valid(cpu))
		return -EINVAL;

	plic_irq_disable(desc);

	cpu_affinity_copy(desc->affinity, affinity);

	plic_irq_enable(desc);

	return 0;
}

static void plic_setup(struct plic_intc_desc *d)
{
	int i = 0, hartid = 0, irq = 0;
	void *enreg = NULL, *hartreg = NULL;

	for (i = 0; i < CONFIG_NR_CPUS; i++) {
		hartid = hartid_of(i);

		enreg = d->regs + CONTEXT_ENABLE_BASE +
				(hartid * 2) * CONTEXT_ENABLE_SIZE;
		hartreg = d->regs + CONTEXT_BASE +
				(hartid * 2) * CONTEXT_SIZE;

		if (hartid && !d->hart0_supervisor_supported) {
			enreg -= CONTEXT_ENABLE_SIZE;
			hartreg -= CONTEXT_SIZE;
		}

		/* clear M-Mode */
		for (irq = 1; irq <= d->max; irq++)
			plic_clear_enable(enreg, irq);

		/* permits all external interrupts */
		iowrite32(0, hartreg + CONTEXT_THRESHOLD);

		/* clear S-Mode */
		enreg += CONTEXT_ENABLE_SIZE;
		for (irq = 1; irq <= d->max; irq++)
			plic_clear_enable(enreg, irq);

		/* permits all external interrupts */
		hartreg += CONTEXT_SIZE;
		iowrite32(0, hartreg + CONTEXT_THRESHOLD);
	}

	/* priority of all external interrupts is 1 (lowest) */
	for (irq = 0; irq <= d->max; irq++)
		iowrite32(1, d->regs + PRIORITY_BASE + irq * 4);
}

static void plic_resume(struct irq_controller *ic)
{
	plic_setup(&plic_desc);
}

static const struct irq_controller_ops plic_intc_ops = {
	.name = "riscv,plic",
	.irq_enable	= plic_irq_enable,
	.irq_disable = plic_irq_disable,
	.irq_set_affinity = plic_set_affinity,

	.irq_controller_resume = plic_resume
};

static int __init plic_parse_dts(struct plic_intc_desc *d,
	struct device_node *dn)
{
	int ret = -1;
	unsigned long addr = 0;
	size_t size = 0;
	unsigned int hart0_machineuser_only = false;
	unsigned int irqs[2] = {0};

	ret = of_read_property_addr_size(dn, "reg", 0, &addr, &size);
	if (ret)
		return -1;

	d->regs = iomap(addr, size);

	ret = of_property_read_u32_array(dn, "interrupts", irqs, 2);
	if (ret)
		return -1;

	d->hwirq = IS_ENABLED(CONFIG_RISCV_S_MODE) ? irqs[0] : irqs[1];

	if (of_property_read_u32(dn, "hart0-machine-user-only",
			&hart0_machineuser_only) == 0)
		d->hart0_supervisor_supported = !hart0_machineuser_only;
	else
		d->hart0_supervisor_supported = __hart0_supervisor_supported;

	ret = of_property_read_u32(dn, "max-irqs", &d->max);
	if (ret)
		return -1;

	d->dn = dn;

	IMSG("init %s %d irqs @ %d\n", dn->id.compat, d->max, d->hwirq);
	return 0;
}

static void plic_link_parent(void)
{
	struct plic_intc_desc *d = &plic_desc;

	/* percpu link(register/enable) the plic @ its parent controller */
	irq_of_register(d->dn, d->hwirq, plic_irq_handler, d->controller);
}
PERCPU_INIT_ROOT(plic_link_parent);

static void __init plic_intc_init(struct device_node *dn)
{
	struct plic_intc_desc *d = &plic_desc;

	if (plic_parse_dts(d, dn) != 0)
		return;

	plic_setup(d);

	/*
	 * create an interrupt controller, link it with its parent
	 * controller later @ percpu routine -> plic_link_parent()
	 */
	d->controller = irq_create_controller(d->dn, d->max + 1, &plic_intc_ops);
}
IRQ_CONTROLLER(plic, "riscv,plic", plic_intc_init);
