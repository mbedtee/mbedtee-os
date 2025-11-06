// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * RISCV APLIC Interrupt-controller
 */

#include <io.h>
#include <of.h>
#include <kmap.h>
#include <trace.h>
#include <bitops.h>
#include <tevent.h>
#include <interrupt.h>

#include <intc-aplic-imsic.h>

#define APLIC_PERCPU_IDC(hartid) (aplic->regs + APLIC_IDC_BASE + \
		(hartid) * APLIC_IDC_SIZE)

struct aplic_desc {
	/* max interrupts in APLIC */
	unsigned int max;

	bool msi_mode;

	/* physial base address of M-mode */
	unsigned long phys_addr_m;
	/* memory-mapped base address*/
	void *regs;
};

static void aplic_percpu_init(void);

static void aplic_irq_enable(struct irq_desc *d)
{
	struct aplic_desc *aplic = d->controller->data;

	iowrite32(d->hwirq, aplic->regs + APLIC_SETIENUM);
}

static void aplic_irq_disable(struct irq_desc *d)
{
	struct aplic_desc *aplic = d->controller->data;

	iowrite32(d->hwirq, aplic->regs + APLIC_CLRIENUM);
}

static void aplic_irq_handler(void *data)
{
	unsigned int irq = 0;
	struct irq_controller *ic = data;
	struct aplic_desc *aplic = ic->data;
	unsigned int hartid = percpu_hartid();
	void *idc = APLIC_PERCPU_IDC(hartid);

	/* read CLAIMI will also clear the pending stat */
	while ((irq = ioread32(idc + APLIC_IDC_CLAIMI)))
		irq_generic_invoke(ic, irq >> 16);
}

static int aplic_set_affinity(struct irq_desc *d,
	const struct cpu_affinity *affinity, bool force)
{
	unsigned int cpu = -1;
	struct cpu_affinity tmp;
	struct aplic_desc *aplic = d->controller->data;
	void *target = aplic->regs + APLIC_TARGET_BASE;

	if (!aplic->msi_mode) {
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

		/*
		 * target register format when Direct mode:
		 *
		 * bits 31:18 Hart Index (WLRL)
		 * bits 7:0
		 * IPRIO (WARL)
		 */
		iowrite32((hartid_of(cpu) << 18) | APLIC_DEFAULT_PRIO,
			target + (d->hwirq - 1) * BYTES_PER_INT);
	} else {
		if (IS_ENABLED(CONFIG_RISCV_IMSIC)) {
			struct irq_desc *dparent = d->parent;
			struct imsic_desc *imsic = dparent->controller->data;
			unsigned int id = IMSIC_IRQ_ID_OF(dparent->hwirq);
			unsigned int dstcpu = IMSIC_IRQ_CPU_OF(dparent->hwirq);
			unsigned int oldval = ioread32(target + (d->hwirq - 1) * BYTES_PER_INT);

			/* shall be ensured by parent-set-affinity func */
			if (!cpu_affinity_isset(affinity, dstcpu))
				return -EINVAL;

			/*
			 * target register format when MSI mode:
			 *
			 * bits 31:18 Hart Index (WLRL)
			 * bits 17:12 Guest Index (WLRL)
			 * bits 10:0 EIID (WARL)
			 */
			iowrite32((hartid_of(dstcpu) << 18) | (0 << 12) | id,
					target + (d->hwirq - 1) * BYTES_PER_INT);

			imsic_post_set_affinity(dparent, cpuid_of(oldval >> 18), oldval & 0x3ff);
		}
	}

	cpu_affinity_copy(d->affinity, affinity);

	return 0;
}

static int aplic_set_type(struct irq_desc *d, unsigned int type)
{
	struct aplic_desc *aplic = d->controller->data;
	void *srccfg = aplic->regs + APLIC_SOURCECFG_BASE;
	unsigned int val = 0;

	switch (type) {
	case IRQ_TYPE_LEVEL_LOW:
		val = APLIC_SOURCECFG_LEVEL_LOW;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		val = APLIC_SOURCECFG_LEVEL_HIGH;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		val = APLIC_SOURCECFG_EDGE_FALL;
		break;
	case IRQ_TYPE_EDGE_RISING:
		val = APLIC_SOURCECFG_EDGE_RISE;
		break;
	default:
		EMSG("possibly wrong type %d\n", type);
		return -EINVAL;
	}

	iowrite32(val, srccfg + (d->hwirq - 1) * BYTES_PER_INT);

	return 0;
}

static void aplic_setup(struct aplic_desc *aplic)
{
	int i = 0;

	/* domaincfg - DM=0, BE=0, IE=0 */
	iowrite32(0, aplic->regs + APLIC_DOMAINCFG);

	/* Disable all */
	for (i = 0; i < aplic->max; i += BITS_PER_INT)
		iowrite32(0xFFFFFFFF, aplic->regs +
			APLIC_CLRIE_BASE + APLIC_REG_OFFSET(i));

	/* Clear sourcecfg/target for all */
	for (i = 1; i < aplic->max; i++) {
		iowrite32(0, aplic->regs + APLIC_SOURCECFG_BASE
				+ (i - 1) * BYTES_PER_INT);
		iowrite32(0, aplic->regs + APLIC_TARGET_BASE
				+ (i - 1) * BYTES_PER_INT);
	}

	/* Clear pending for all */
	for (i = 0; i < aplic->max; i += BITS_PER_INT)
		iowrite32(0xFFFFFFFF, aplic->regs +
			APLIC_CLRIP_BASE + APLIC_REG_OFFSET(i));

	/* domaincfg - DM=0, BE=0, IE=1 */
	iowrite32(APLIC_DOMAINCFG_IE, aplic->regs + APLIC_DOMAINCFG);

	/* request APLIC delegation from M-Mode */
	if (IS_ENABLED(CONFIG_RISCV_S_MODE))
		ecall(ECALL_APLIC_D, aplic->phys_addr_m,
			APLIC_SOURCECFG_BASE, aplic->max);
}

static void aplic_setup_msi(struct aplic_desc *aplic,
	struct irq_controller *ic)
{
	if (aplic->msi_mode && IS_ENABLED(CONFIG_RISCV_IMSIC)) {
		struct imsic_desc *imsic = ic->parent->data;

		uint64_t ppn = 0;
		uint32_t vl = 0;
		uint32_t vh = 0;

		ppn = imsic->phys_addr >> APLIC_xMSICFGADDR_PPN_SHIFT;

		/*
		 * MSI address configuration:
		 *
	 	 * APLIC_xMSICFGADDR:
		 * bits 31:0 Low Base PPN (WARL)
		 *
	 	 * APLIC_xMSICFGADDRH:
		 * bit  31    Lock
		 * bits 28:24 HHXS (WARL)
		 * bits 22:20 LHXS (WARL)
		 * bits 18:16 HHXW (WARL)
		 * bits 15:12 LHXW (WARL)
		 * bits 11:0  High Base PPN (WARL)
		 */
		vl = ppn & -1u;
		vh = (ppn >> 32) & 0x3ff;
		vh |= imsic->hart_index_bits << 12;
		vh |= imsic->guest_index_bits << 20;

		if (!IS_ENABLED(CONFIG_RISCV_S_MODE)) {
			iowrite32(vl, aplic->regs + APLIC_MMSICFGADDR);
			iowrite32(vh, aplic->regs + APLIC_MMSICFGADDRH);
		} else {
			ecall(ECALL_APLIC_MSI, aplic->phys_addr_m +
					APLIC_MMSICFGADDR, vl, vh);
			ecall(ECALL_APLIC_MSI, aplic->phys_addr_m +
					APLIC_SMSICFGADDR, vl, vh);
		}

		/* domaincfg - set DM for MSI */
		iowrite32(ioread32(aplic->regs + APLIC_DOMAINCFG) |
			APLIC_DOMAINCFG_DM, aplic->regs + APLIC_DOMAINCFG);
	}
}

static int __init aplic_parse_dts(struct aplic_desc *d,
	struct device_node *dn)
{
	int ret = -1;
	unsigned long addr = 0;
	size_t size = 0;
	struct device_node *parent = NULL;

	ret = of_parse_io_resource(dn, 0, &addr, &size);
	if (ret)
		return ret;

	d->phys_addr_m = addr;

	if (IS_ENABLED(CONFIG_RISCV_S_MODE)) {
		ret = of_parse_io_resource(dn, 1, &addr, &size);
		if (ret)
			return ret;
	}

	parent = of_irq_find_parent(dn);
	if (parent && !strcmp(parent->id.compat, "riscv,imsic"))
		d->msi_mode = true;

	ret = of_irq_parse_max(dn, &d->max);
	if (ret || (d->max >= APLIC_MAX_INT))
		return -EINVAL;

	d->regs = iomap(addr, size);

	IMSG("init %s %d irqs\n", dn->id.name, d->max);

	return 0;
}

static void aplic_resume(struct irq_controller *ic)
{
	aplic_setup(ic->data);
	aplic_setup_msi(ic->data, ic);
	aplic_percpu_init();
}

static const struct irq_controller_ops aplic_intc_ops = {
	.name = "riscv,aplic",
	.irq_enable	= aplic_irq_enable,
	.irq_disable = aplic_irq_disable,
	.irq_set_affinity = aplic_set_affinity,
	.irq_set_type = aplic_set_type,

	.irq_controller_resume = aplic_resume
};

static void aplic_percpu_init(void)
{
	struct aplic_desc *aplic = NULL;
	struct irq_controller *ic = NULL;

	/*
	 * currently there is only one aplic in one RISCV system.
	 * if there are multi-aplic in one RISCV system in the future,
	 * add a irq_for_each_matching_controller() to handle them all.
	 */
	ic = irq_matching_ops_controller(&aplic_intc_ops);

	aplic = ic->data;

	/*
	 * normally there is no IDC when MSI mode
	 */
	if (aplic->msi_mode)
		return;

	/*
	 * set the threshold to 0 - means to delivery all enabled intsrc to this hart
	 */
	iowrite32(0, APLIC_PERCPU_IDC(percpu_hartid()) + APLIC_IDC_ITHRESHOLD);

	iowrite32(0, APLIC_PERCPU_IDC(percpu_hartid()) + APLIC_IDC_IFORCE);

	/* 1 = interrupt delivery is enabled for this hart */
	iowrite32(1, APLIC_PERCPU_IDC(percpu_hartid()) + APLIC_IDC_IDELIVERY);

	/* percpu aplic chained to its parent controller */
	irq_chained_register(ic, IS_ENABLED(CONFIG_RISCV_S_MODE), aplic_irq_handler, ic);
}
PERCPU_INIT_ROOT(aplic_percpu_init);

static void __init aplic_intc_init(struct device_node *dn)
{
	struct aplic_desc *aplic = NULL;
	struct irq_controller *ic = NULL;

	aplic = kmalloc(sizeof(*aplic));
	if (aplic == NULL)
		return;

	if (aplic_parse_dts(aplic, dn) != 0)
		return;

	aplic_setup(aplic);

	/*
	 * create an interrupt controller, it also will be chained to its
	 * parent controller later at percpu routine -> aplic_percpu_init()
	 */
	ic = irq_create_controller(dn, aplic->max, &aplic_intc_ops, aplic);

	aplic_setup_msi(aplic, ic);
}
IRQ_CONTROLLER(aplic, "riscv,aplic", aplic_intc_init);
