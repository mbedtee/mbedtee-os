// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GICv1/v2 Driver for the AArch32@ARMV7-A with Security Extension
 */

#include <io.h>
#include <of.h>
#include <ipi.h>
#include <defs.h>
#include <kmap.h>
#include <trace.h>
#include <driver.h>
#include <thread.h>

#include <interrupt.h>
#include <generated/autoconf.h>

#define GICD_VERSION1				(1)
#define GICD_VERSION2				(2)

#define GICD_CTRL					(0x000)
#define GICD_TYPE					(0x004)
#define GICD_IGROUP					(0x080)
#define GICD_ISENABLER				(0x100)
#define GICD_ICENABLER				(0x180)
#define GICD_ICPENDR                (0x280)
#define GICD_ICACTIVER              (0x380)
#define GICD_IPRIORITY				(0x400)
#define GICD_ITARGETS				(0x800)
#define GICD_ICFG					(0xC00)
#define GICD_NSACR					(0xE00)
#define GICD_SGI					(0xF00)
#define GICD_ICPIDR2				(0xFE8)

#define GICC_CTLR					(0x00)
#define GICC_PMR					(0x04)
#define GICC_BPR					(0x08)
#define GICC_IAR					(0x0C)
#define GICC_EOIR					(0x10)
#define GICC_IIDR					(0xFC)
#define GICC_DIR					(0x1000)

#define GICC_IAR_CPUID_MASK			(CONFIG_NR_CPUS - 1)
#define GICC_IAR_CPUID_SHIFT		(10)
#define GICC_IAR_INTERRUPT_MASK		(0x3FF)
#define GICC_SOFTINT_NSATT			(U(1) << 15)
#define GICC_SOFTINT_TARGET			(U(1) << 16)

#define GICC_VERSION_SHIFT			(16)
#define GICC_VERSION_MASK			(0xF)
#define GICC_REVISION_SHIFT			(12)
#define GICC_REVISION_MASK			(0xF)

#define GIC_SECURE_SGI_START		(8)
#define GIC_SPI_START				(32)

#define GIC_SGI_MAX					U(16)

#define GICD_VERSION_SHIFT			(4)
#define GICD_VERSION_MASK			(0xF)

#define GIC_SECURE_PRIORITY_MASK	U(0xFF)
#define GICD_SECURE_PRIORITY		U(0x00)
#define GICC_SECURE_PRIORITY		U(0x80)

#define GIC_REG_OFFSET(n)			(BYTES_PER_INT * ((n) / BITS_PER_INT))
#define GIC_BIT_OFFSET(n)			((n) % BITS_PER_INT)

#define GIC_MAX_INT					(1020)
#define GIC_SUPRIOUS_INT1			(1022)
#define GIC_SUPRIOUS_INT2			(1023)

#define GIC_IS_SPI(x) ((x) >= GIC_SPI_START)

static struct gic_desc {
	void *dist_base;
	void *cpuif_base;
	struct irq_controller *controller;
	struct irq_controller *softint_controller;
	uint32_t total;
	struct spinlock lock;
	int8_t version;
	bool security_extn;
} gic_desc = {0};

static inline void gic_write_dist(uint32_t val, uint32_t offset)
{
	iowrite32(val, gic_desc.dist_base + offset);
}

static inline uint32_t gic_read_dist(uint32_t offset)
{
	return ioread32(gic_desc.dist_base + offset);
}

static inline void gic_write_cpuif(uint32_t val, uint32_t offset)
{
	iowrite32(val, gic_desc.cpuif_base + offset);
}

static inline uint32_t gic_read_cpuif(uint32_t offset)
{
	return ioread32(gic_desc.cpuif_base + offset);
}

static inline int gic_softint2sgi(unsigned int softint)
{
	if (softint < SOFTINT_MAX)
		return softint + GIC_SECURE_SGI_START;

	return -1;
}

static inline int gic_sgi2softint(unsigned int sgi)
{
	if (sgi < GIC_SECURE_SGI_START + SOFTINT_MAX)
		return sgi - GIC_SECURE_SGI_START;

	return -1;
}

static void gic_clear_enable(unsigned int gic_num)
{
	uint32_t val = 1 << GIC_BIT_OFFSET(gic_num);

	gic_write_dist(val, GICD_ICENABLER +
		GIC_REG_OFFSET(gic_num));
}

static void gic_set_enable(unsigned int gic_num)
{
	uint32_t val = 0;
	uint32_t reg_off = GICD_ISENABLER +
			GIC_REG_OFFSET(gic_num);

	val = gic_read_dist(reg_off);

	val |= (1 << GIC_BIT_OFFSET(gic_num));

	gic_write_dist(val, reg_off);
}

static inline void gic_eoir(uint32_t iar)
{
	gic_write_cpuif(iar, GICC_EOIR);
}

static void gic_configure_group(unsigned int gic_num)
{
	uint32_t reg_off = GICD_IGROUP + GIC_REG_OFFSET(gic_num);
	uint32_t val = gic_read_dist(reg_off);

	/* configure the group to SECURE */
	val &= ~(1U << GIC_BIT_OFFSET(gic_num));
	gic_write_dist(val, reg_off);
}

static void gic_configure_prio(unsigned int gic_num)
{
	int reg_shift = 0;
	uint32_t reg_off = GICD_IPRIORITY + (gic_num & ~3);
	uint32_t val = gic_read_dist(reg_off);

	val = gic_read_dist(reg_off);

	reg_shift = (gic_num % 4) * 8;
	val &= ~(GIC_SECURE_PRIORITY_MASK << reg_shift);
	val |= GICD_SECURE_PRIORITY << reg_shift;

	gic_write_dist(val, reg_off);
}

static void gic_configure_target(unsigned int gic_num,
	unsigned int target_cpu)
{
	/*
	 * 8-bit CPU targets field for each interrupt
	 * a value of 0x3 means that the Pending
	 * interrupt is sent to processors 0 and 1
	 */
	uint32_t reg_off = GICD_ITARGETS + (gic_num & ~3);
	uint32_t bit_off = (gic_num % 4) * 8;

	gic_write_dist((gic_read_dist(reg_off) & ~(0xFF << bit_off)) |
		(1 << (target_cpu + bit_off)), reg_off);
}

static void gic_dist_init(void)
{
	uint32_t i = 0;
	uint32_t total = 0;
	uint32_t version = 0;
	uint32_t typer = 0;

	/*
	 * interrupts not forwarded
	 */
	gic_write_dist(0, GICD_CTRL);

	/*
	 * maximum number of interrupts is 32(N+1)
	 */
	typer = gic_read_dist(GICD_TYPE);
	total = typer & 0x1F;
	total = 32 * (total + 1);
	gic_desc.total = min(total, (uint32_t)GIC_MAX_INT);

	/*
	 * validate the version
	 */
	version = ((gic_read_dist(GICD_ICPIDR2) >> GICD_VERSION_SHIFT)
			& GICD_VERSION_MASK);

	gic_desc.security_extn = (typer >> 10) & 1;

	IMSG("%d interrupts @ GICDv%d SecurityExtn %d\n",
		(int)total, (int)version, gic_desc.security_extn);

	if (version != gic_desc.version)
		WMSG("GIC version mismatch\n");

	/*
	 * Disable All SPIs
	 *
	 * ID0-ID15 for SGIs.
	 * ID16-ID31 for PPIs.
	 * ID32-ID1019 for SPIs.
	 */
	for (i = GIC_SPI_START; i < total; i += BITS_PER_INT)
		gic_write_dist(0xFFFFFFFF, GICD_ICENABLER + GIC_REG_OFFSET(i));

	/*
	 * GICD_NSACR: No Non-secure access is permitted for Group 0 SPIs
	 */
	for (i = GIC_SPI_START; i < total; i += 16)
		gic_write_dist(0, GICD_NSACR + ((i / 16) * BYTES_PER_INT));

	/*
	 * Deault Route SPIs to group1 (non-secure),
	 * will route to group0 when needed
	 */
	for (i = GIC_SPI_START; i < total; i += BITS_PER_INT)
		gic_write_dist(0xFFFFFFFF, GICD_IGROUP + GIC_REG_OFFSET(i));

	/*
	 * Both group0/group1 interrupts will be forwarded
	 */
	gic_write_dist(3, GICD_CTRL);
}

static void gic_cpuif_init(void)
{
	int i = 0;
	int version = 0, revision = 0;

	/*
	 * disable
	 */
	gic_write_cpuif(0, GICC_CTLR);

	/*
	 * validate the version
	 */
	version = (gic_read_cpuif(GICC_IIDR) >> GICC_VERSION_SHIFT) & GICC_VERSION_MASK;
	revision = (gic_read_cpuif(GICC_IIDR) >> GICC_REVISION_SHIFT) & GICC_REVISION_MASK;

	IMSG("GICCv%d.%d @ CPU%u\n", version, revision, percpu_id());

	if (version != gic_desc.version)
		WMSG("GIC version mismatch\n");

	/*
	 * handling the bank registers for each cpu interface
	 *
	 * Disable all SGI/PPI
	 */
	gic_write_dist(0xFFFFFFFF, GICD_ICENABLER);
	gic_write_dist(0xFFFFFFFF, GICD_ICPENDR);
	gic_write_dist(0xFFFFFFFF, GICD_ICACTIVER);

	/*
	 * GICD_ICFG: Corresponding interrupt is level-sensitive
	 * GICD_NSACR: No Non-secure access is permitted for Group 0 SGI
	 */
	for (i = 0; i < GIC_SPI_START; i += 16) {
		gic_write_dist(0, GICD_ICFG + ((i / 16) * BYTES_PER_INT));
		gic_write_dist(0, GICD_NSACR + ((i / 16) * BYTES_PER_INT));
	}

	/*
	 * Only interrupts with higher priority
	 * than the value in this register are
	 * forwarded to the processor
	 *
	 * lower value for higher priority
	 */
	gic_write_cpuif(GICC_SECURE_PRIORITY, GICC_PMR);

	/*
	 * Deault Route SGI/PPI to group1 (non-secure),
	 * will route to group0 when needed
	 */
	gic_write_dist(0xFFFFFFFF, GICD_IGROUP);

	gic_write_cpuif(0, GICC_BPR);

	/*
	 * Enable group0 interrupts (1 << 0)
	 * Enable group1 interrupts (1 << 1)
	 * Enable FIQ (1 << 3)
	 */
	gic_write_cpuif(0xB, GICC_CTLR);
}

static void gic_enable_int(struct irq_desc *d)
{
	unsigned long flags = 0;
	unsigned int gic_num = d->hwirq, cpu = 0;

	spin_lock_irqsave(&gic_desc.lock, flags);

	gic_configure_group(gic_num);
	gic_configure_prio(gic_num);
	gic_set_enable(gic_num);

	if (GIC_IS_SPI(gic_num)) {
		cpu = cpu_affinity_next_one(d->affinity, 0);
		gic_configure_target(gic_num, cpu);
	}

	spin_unlock_irqrestore(&gic_desc.lock, flags);
}

static void gic_disable_int(struct irq_desc *d)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&gic_desc.lock, flags);
	gic_clear_enable(d->hwirq);
	spin_unlock_irqrestore(&gic_desc.lock, flags);
}

static int gic_set_affinity(struct irq_desc *desc,
	const struct cpu_affinity *affinity)
{
	unsigned int cpu;
	struct cpu_affinity tmp;

	cpu_affinity_and(&tmp, affinity, cpus_online);

	cpu = cpu_affinity_next_one(&tmp, 0);
	if (!cpu_affinity_valid(cpu))
		return -EINVAL;

	gic_disable_int(desc);

	cpu_affinity_copy(desc->affinity, affinity);

	gic_enable_int(desc);

	return 0;
}

/*
 * Generate a softint by using HW SGI on the
 * processor specified by @cpu_id
 *
 * ARM strongly recommends that all processors reserve:
 * ID0-ID7 for Non-secure SGIs
 * ID8-ID15 for Secure SGIs.
 */
static void gic_softint_raise(struct irq_desc *d, unsigned int cpu_id)
{
	uint32_t nsatt = 0;
	unsigned long flags = 0;
	int gic_num = gic_softint2sgi(d->hwirq);

	/* not support security_extn, so should not trigger NS SGIs */
	if (!gic_desc.security_extn && gic_num <= GIC_SECURE_SGI_START)
		return;

	spin_lock_irqsave(&gic_desc.lock, flags);

	if (gic_num >= 0) {
		nsatt = gic_read_dist(GICD_IGROUP) & (1 << gic_num);

		gic_write_dist(gic_num | (GICC_SOFTINT_TARGET << cpu_id) |
						(nsatt ? GICC_SOFTINT_NSATT : 0), GICD_SGI);
	}
	spin_unlock_irqrestore(&gic_desc.lock, flags);
}

/*
 * Get the parent hwirq/handler of the specified #d
 */
static int gic_softint_parent(struct irq_desc *d,
	unsigned int *hwirq, irq_handler_t *handler)
{
	int gic_num = 0;

	if (!(d->controller->flags & IRQCTRL_SOFTINT))
		return -EINVAL;

	gic_num = gic_softint2sgi(d->hwirq);
	if (gic_num < 0)
		return -EINVAL;

	*hwirq = gic_num;
/* use the child's handler directly, no need to do extra eoi */
	*handler = d->handler;
	return 0;
}

static void gic_suspend(struct irq_controller *ic)
{
	gic_write_cpuif(0, GICC_CTLR);
}

static void gic_resume(struct irq_controller *ic)
{
	gic_dist_init();
	gic_cpuif_init();
}

static bool gic_is_percpu(struct irq_desc *d)
{
	return !GIC_IS_SPI(d->hwirq);
}

static const struct irq_controller_ops gic_interrupt_ops = {
	.name = "arm,gic",

	.irq_enable = gic_enable_int,
	.irq_disable = gic_disable_int,

	.irq_is_percpu = gic_is_percpu,

	.irq_resume = gic_enable_int,
	.irq_suspend = gic_disable_int,

	.irq_set_affinity = gic_set_affinity,

	.irq_controller_suspend = gic_suspend,
	.irq_controller_resume = gic_resume,
};

static const struct irq_controller_ops gic_softint_ops = {
	.name = "arm,gic,softint",

	.irq_parent = gic_softint_parent,
	.irq_send = gic_softint_raise,
};

static void gic_handler(struct thread_ctx *regs)
{
	uint32_t iar = 0, gic_num = 0, handled = 0;

	/*
	 * to get the source CPU_ID which triggered a SGI, use:
	 * (iar >> GICC_IAR_CPUID_SHIFT) & GICC_IAR_CPUID_MASK
	 */
	do {
		iar = gic_read_cpuif(GICC_IAR);
		gic_num = iar & GICC_IAR_INTERRUPT_MASK;

		if (gic_num >= GIC_MAX_INT)
			break;

		gic_eoir(iar);
		irq_generic_invoke(gic_desc.controller, gic_num);
		handled++;
	} while (1);

	/* patch for the weird AArch64 + GICv2v1 SoC */
#if defined(CONFIG_AARCH64)
	/* maybe NS Interrupt */
	if (IS_ENABLED(CONFIG_REE) && (!handled || (gic_num == 1022)))
		smc_call(0, 0, 0, 0);
	else
		gic_write_cpuif(0xB, GICC_CTLR);
#endif
}

bool gic_has_security_extn(void)
{
	return gic_desc.security_extn;
}

static void __init gic_parse_dts(struct device_node *dn)
{
	unsigned long gicd = 0, gicc = 0;
	size_t size = 0;
	struct gic_desc *d = &gic_desc;

	d->version = dn->id.compat[strlen(dn->id.compat) - 1] - '0';

	of_read_property_addr_size(dn, "reg", 0, &gicd, &size);
	d->dist_base = iomap(gicd, size);
	IMSG("gic-dist@v%d 0x%lx, size: 0x%x\n", d->version, gicd, (int)size);

	of_read_property_addr_size(dn, "reg", 1, &gicc, &size);
	d->cpuif_base = iomap(gicc, size);
	IMSG("gic-cpuif@v%d 0x%lx, size: 0x%x\n", d->version, gicc, (int)size);

	/* For the weird AArch64 + GICv2v1 SoC */
	if (IS_ENABLED(CONFIG_AARCH64))
		smc_call(3, gicd + GICD_SGI, gicc + GICC_CTLR, 0);
}

static void gic_percpu_init(void)
{
	gic_cpuif_init();
}
PERCPU_INIT_ROOT(gic_percpu_init);

/*
 * Initialize the ARM GIC
 */
static void __init gic_init(struct device_node *dn)
{
	struct gic_desc *d = &gic_desc;

	gic_parse_dts(dn);

	gic_dist_init();

	/*
	 * create interrupt controller, this is the root, no parent.
	 * combo means: PERCPU(Local SGI/PPI) + Shared(External SPI)
	 */
	d->controller = irq_create_combo_controller(dn,
			d->total, &gic_interrupt_ops);

	/* create the Softint controller */
	d->softint_controller = irq_create_softint_controller(
		d->controller, SOFTINT_MAX, &gic_softint_ops);

	irq_set_root_handler(gic_handler);
}
IRQ_CONTROLLER(gicv1, "arm,gic-v1", gic_init);
IRQ_CONTROLLER(gicv2, "arm,gic-v2", gic_init);
