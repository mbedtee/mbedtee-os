// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>
 * RISCV aclint / Andes PLICSW Interrupt Controller
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
#define RISCV_SOFTINT_SOURCE (IS_ENABLED(CONFIG_RISCV_S_MODE) ? SSIE : MSIE)

/*
 * Andes PLICSW register offsets.
 * PLICSW is a PLIC-style software interrupt controller
 * with a completely different register layout from ACLINT MSWI.
 */
#define PLICSW_PRIORITY_BASE    0x4
#define PLICSW_PENDING_BASE     0x1000
#define PLICSW_ENABLE_BASE      0x2000
#define PLICSW_ENABLE_STRIDE    0x80
#define PLICSW_THRESHOLD_BASE   0x200000
#define PLICSW_THRESHOLD_STRIDE 0x1000

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
	int regidx = 0;
	unsigned long base_addr = 0;
	struct riscv_desc *d = NULL;
	struct irq_controller *ic = NULL;

	d = kmalloc(sizeof(*d));
	if (!d)
		return;

	regidx = IS_ENABLED(CONFIG_RISCV_S_MODE) ? 1 : 0;

	/* base register for Softint */
	d->base = of_iomap(dn, regidx);

	if (IS_ENABLED(CONFIG_RISCV_S_MODE)) {
		d->sswi_exist = d->base ? riscv_io_readable(d->base) : 0;
		/* get the mswi base for S-Mode forwarding the swi to M-Mode */
		if (!d->sswi_exist) {
			iounmap(d->base);
			of_parse_io_resource(dn, 0, &base_addr, NULL);
			d->base = (void *)base_addr;
		}

		IMSG("sswi_exist: %d\n", d->sswi_exist);
	}

	/* create interrupt controller, this is the root, no parent */
	ic = irq_create_percpu_controller(dn, 16, &riscv_irq_ops, d);

	irq_set_root_handler(riscv_irq_handler);

	/*
	 * provides one SGI source for softint framework
	 * if the imsic present, imsic provides the SGI instead clint.
	 */
	if (!of_find_compatible_node(NULL, "riscv,imsic") && d->base)
		softint_init(ic, &(unsigned int){RISCV_SOFTINT_SOURCE}, 1);
}
IRQ_CONTROLLER(riscv, "riscv,aclint", riscv_intc_init);

/*
 * Flag shared with M-mode assembly (riscv-exception.S).
 * When set, M-mode uses PLICSW protocol for IPI delivery
 * instead of ACLINT MSWI.
 */
extern unsigned long __plicsw;

static const struct irq_controller_ops plicsw_irq_ops = {
	.name = "andestech,plicsw",

	.irq_enable = riscv_irq_enable,
	.irq_disable = riscv_irq_disable,

	.irq_suspend = riscv_irq_disable,
	.irq_resume = riscv_irq_enable,

	.irq_send = riscv_softint_raise,
};

/*
 * Initialize Andes PLICSW as the software interrupt controller.
 *
 * PLICSW uses a PLIC-like register layout. Each hart is assigned
 * a dedicated IRQ source (hartid+1). The M-mode handler uses
 * pending/claim/complete registers instead of ACLINT MSWI.
 */
static void __init plicsw_intc_init(struct device_node *dn)
{
	int cpu = 0;
	unsigned long hartid = 0;
	unsigned long base_addr = 0;
	struct riscv_desc *d = NULL;
	struct irq_controller *ic = NULL;
	void *base = NULL;

	d = kmalloc(sizeof(*d));
	if (!d)
		return;

	/*
	 * Map only the region we need: up to threshold registers.
	 * Actual size: THRESHOLD_BASE + STRIDE * NR_CPUS = ~0x204000
	 * DTS declares full 0x400000 matching QEMU MMIO, but we
	 * only access up to the threshold + claim/complete registers.
	 */
	of_parse_io_resource(dn, 0, &base_addr, NULL);
	base = iomap(base_addr, PLICSW_THRESHOLD_BASE +
		PLICSW_THRESHOLD_STRIDE * CONFIG_NR_CPUS);
	if (!base) {
		kfree(d);
		return;
	}

	/*
	 * Configure PLICSW for each hart:
	 * - Use source (hartid+1) as the IPI source for each hart
	 * - Set priority = 1 so it exceeds the threshold
	 * - Enable only source (hartid+1) for context hartid
	 * - Set threshold = 0 to accept all priorities > 0
	 */
	for_each_possible_cpu(cpu) {
		hartid = hartid_of(cpu);

		/* Set priority for source (hartid+1) */
		iowrite32(1, (char *)base + PLICSW_PRIORITY_BASE +
			hartid * sizeof(uint32_t));

		/* Enable source (hartid+1) for context hartid */
		iowrite32(1U << (hartid + 1), (char *)base +
			PLICSW_ENABLE_BASE + hartid * PLICSW_ENABLE_STRIDE);

		/* Set threshold = 0 for context hartid */
		iowrite32(0, (char *)base + PLICSW_THRESHOLD_BASE +
			hartid * PLICSW_THRESHOLD_STRIDE);
	}

	iounmap(base);

	/* Physical base already parsed above for iomap */
	d->base = (void *)base_addr;
	d->sswi_exist = false;

	/* Tell M-mode to use PLICSW protocol */
	__plicsw = 1;

	IMSG("plicsw @ 0x%lx\n", base_addr);

	ic = irq_create_percpu_controller(dn, 16, &plicsw_irq_ops, d);

	irq_set_root_handler(riscv_irq_handler);

	if (!of_find_compatible_node(NULL, "riscv,imsic") && d->base)
		softint_init(ic, &(unsigned int){RISCV_SOFTINT_SOURCE}, 1);
}
IRQ_CONTROLLER(plicsw, "andestech,plicsw", plicsw_intc_init);
