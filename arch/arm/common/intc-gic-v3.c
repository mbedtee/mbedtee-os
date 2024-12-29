// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GICv3 Driver for the AArch64 (2 Security States)
 */

#include <io.h>
#include <of.h>
#include <ipi.h>
#include <defs.h>
#include <kmap.h>
#include <delay.h>
#include <trace.h>
#include <driver.h>
#include <thread.h>

#include <interrupt.h>
#include <generated/autoconf.h>

#define GICD_VERSION                (3)

#define GICD_CTRL                   (0x0000)
#define GICD_TYPE                   (0x0004)
#define GICD_IGROUPR                (0x0080)
#define GICD_ISENABLER              (0x0100)
#define GICD_ICENABLER              (0x0180)
#define GICD_ICACTIVER              (0x0380)
#define GICD_IPRIORITY              (0x0400)
#define GICD_ICFGR                  (0x0C00)
#define GICD_IGRPMODR               (0x0D00)
#define GICD_NSACR                  (0x0E00)
#define GICD_IROUTER                (0x6000)
#define GICD_PIDR2                  (0xFFE8)

#define GICD_VERSION_SHIFT          (4)
#define GICD_VERSION_MASK           (0xF)
#define GICD_CTRL_RWP               (U(1) << 31)

#define GICR_SIZE					(0x20000)
#define GICR_RD_BASE                (0x00000)
#define GICR_SGI_BASE               (0x10000)
#define GICR_CTRL                   (0x0000 + GICR_RD_BASE)
#define GICR_TYPER                  (0x0008 + GICR_RD_BASE)
#define GICR_WAKER                  (0x0014 + GICR_RD_BASE)
#define GICR_PIDR2                  (0xFFE8 + GICR_RD_BASE)
#define GICR_IGROUPR                (0x0080 + GICR_SGI_BASE)
#define GICR_ISENABLER              (0x0100 + GICR_SGI_BASE)
#define GICR_ICENABLER              (0x0180 + GICR_SGI_BASE)
#define GICR_ICACTIVER              (0x0380 + GICR_SGI_BASE)
#define GICR_IPRIORITY              (0x0400 + GICR_SGI_BASE)
#define GICR_ICFGR                  (0x0C00 + GICR_SGI_BASE)
#define GICR_IGRPMODR               (0x0D00 + GICR_SGI_BASE)
#define GICR_NSACR                  (0x0E00 + GICR_SGI_BASE)
#define GICR_WAKER_PROCESSORSLEEP   (U(1) << 1)
#define GICR_WAKER_CHILDRENASLEEP   (U(1) << 2)
#define GICR_CTRL_RWP               (U(1) << 3)
#define GICR_CTRL_UWP               (U(1) << 31)

#define GICR_VERSION_SHIFT          (4)
#define GICR_VERSION_MASK           (0xF)

#define ICC_IAR_INTID_MASK          (0xFFFFFF)

#define PFR_GIC_VERSION_SHIFT       (24)
#define PFR_GIC_VERSION_MASK        (0xF)

#define GIC_SECURE_PRIORITY_MASK    U(0xFF)
#define GICD_SECURE_PRIORITY        U(0x00)
#define GICC_SECURE_PRIORITY        U(0x80)

#define GIC_REG_OFFSET(n)			(BYTES_PER_INT * ((n) / BITS_PER_INT))
#define GIC_BIT_OFFSET(n)			((n) % BITS_PER_INT)

#define GIC_SECURE_SGI_START		(8)

#define GIC_SPI_START               (32)
#define GIC_SGI_MAX                 (U(16))

#define GIC_MAX_INT                 (1020)
#define GIC_SUPRIOUS_INT1           (1022)
#define GIC_SUPRIOUS_INT2           (1023)

#define GIC_IS_SPI(x)				((x) >= GIC_SPI_START)

static struct gic_desc {
	void *dist_base;
	void *rdist_base;
	struct irq_controller *controller;
	struct irq_controller *softint_controller;
	uint32_t total;
	struct spinlock lock;
	int8_t version;
} gic_desc = {0};

#define RDIST_BASE (gic_desc.rdist_base + (GICR_SIZE * percpu_id()))

static inline void gic_write_dist(uint32_t val, uint32_t offset)
{
	iowrite32(val, gic_desc.dist_base + offset);
}

static inline uint32_t gic_read_dist(uint32_t offset)
{
	return ioread32(gic_desc.dist_base + offset);
}

static inline void gic_write_rdist(uint32_t val, uint32_t offset)
{
	iowrite32(val, RDIST_BASE + offset);
}

static inline uint32_t gic_read_rdist(uint32_t offset)
{
	return ioread32(RDIST_BASE + offset);
}

static inline uint64_t gic_read_rdist64(uint32_t offset)
{
	return ioread64(RDIST_BASE + offset);
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

static inline void icc_write_sre(unsigned long val)
{
	write_system_reg(S3_0_C12_C12_5, val);
}
static inline void icc_write_pmr(unsigned long val)
{
	write_system_reg(S3_0_C4_C6_0, val);
}
static inline void icc_write_ctrl(unsigned long val)
{
	write_system_reg(S3_0_C12_C12_4, val);
}
static inline void icc_write_igrpen0(unsigned long val)
{
	write_system_reg(S3_0_C12_C12_6, val);
}
static inline void icc_write_igrpen1(unsigned long val)
{
	write_system_reg(S3_0_C12_C12_7, val);
}
static inline void icc_write_eoir0(unsigned long val)
{
	write_system_reg(S3_0_C12_C8_1, val);
}
static inline void icc_write_eoir1(unsigned long val)
{
	write_system_reg(S3_0_C12_C12_1, val);
}
static inline void icc_write_dir(unsigned long val)
{
	write_system_reg(S3_0_C12_C11_1, val);
}
static inline void icc_write_sgi0r(unsigned long val)
{
	write_system_reg(S3_0_C12_C11_7, val);
}
static inline void icc_write_sgi1r(unsigned long val)
{
	write_system_reg(S3_0_C12_C11_5, val);
}
static inline void icc_write_asgi1r(unsigned long val)
{
	write_system_reg(S3_0_C12_C11_6, val);
}
static inline void icc_write_ap1r0(unsigned long val)
{
	write_system_reg(S3_0_C12_C9_0, val);
}
static inline void icc_write_ap1r1(unsigned long val)
{
	write_system_reg(S3_0_C12_C9_1, val);
}
static inline void icc_write_ap1r2(unsigned long val)
{
	write_system_reg(S3_0_C12_C9_2, val);
}
static inline void icc_write_ap1r3(unsigned long val)
{
	write_system_reg(S3_0_C12_C9_3, val);
}
static inline unsigned long icc_read_ctrl(void)
{
	return read_system_reg(S3_0_C12_C12_4);
}
static inline unsigned long icc_read_sre(void)
{
	return read_system_reg(S3_0_C12_C12_5);
}
static inline unsigned long icc_read_igrpen1(void)
{
	return read_system_reg(S3_0_C12_C12_7);
}
static inline unsigned long icc_read_iar0(void)
{
	return read_system_reg(S3_0_C12_C8_0);
}
static inline unsigned long icc_read_iar1(void)
{
	return read_system_reg(S3_0_C12_C12_0);
}

static inline void gic_dist_wait_rwp(void)
{
	uint32_t in_time = 1000000;

	while (gic_read_dist(GICD_CTRL) & GICD_CTRL_RWP) {
		if (--in_time == 0)
			break;
		udelay(1);
	}

	assert(in_time);
}

static inline void gic_rdist_wait_uwp(void)
{
	uint32_t in_time = 1000000;

	while (gic_read_rdist(GICR_CTRL) &
		(GICR_CTRL_UWP | GICR_CTRL_RWP)) {
		if (--in_time == 0)
			break;
		udelay(1);
	}

	assert(in_time);
}

static void gic_clear_enable(unsigned int gic_num)
{
	uint32_t val = 1 << GIC_BIT_OFFSET(gic_num);
	uint32_t reg_off = GIC_REG_OFFSET(gic_num);
	void *reg = NULL;
	void (*sync_wp)(void) = NULL;

	if (GIC_IS_SPI(gic_num)) {
		reg = gic_desc.dist_base + GICD_ICENABLER + reg_off;
		sync_wp = gic_dist_wait_rwp;
	} else {
		reg_off += percpu_id() * GICR_SIZE;
		reg = gic_desc.rdist_base + GICR_ICENABLER + reg_off;
		sync_wp = gic_rdist_wait_uwp;
	}

	iowrite32(val, reg);

	sync_wp();
}

static void gic_set_enable(unsigned int gic_num)
{
	uint32_t val = 0;
	uint32_t reg_off = GIC_REG_OFFSET(gic_num);
	void *reg = NULL;
	void (*sync_wp)(void) = NULL;

	if (GIC_IS_SPI(gic_num)) {
		reg = gic_desc.dist_base + GICD_ISENABLER + reg_off;
		sync_wp = gic_dist_wait_rwp;
	} else {
		reg_off += percpu_id() * GICR_SIZE;
		reg = gic_desc.rdist_base + GICR_ISENABLER + reg_off;
		sync_wp = gic_rdist_wait_uwp;
	}

	val = ioread32(reg);
	val |= 1U << GIC_BIT_OFFSET(gic_num);
	iowrite32(val, reg);

	sync_wp();
}

static void gic_configure_group(unsigned int gic_num)
{
	uint32_t val = 0;
	uint32_t reg_off = GIC_REG_OFFSET(gic_num);
	void *reg = NULL, *reg_mod = NULL;
	void (*sync_wp)(void) = NULL;

	if (GIC_IS_SPI(gic_num)) {
		reg = gic_desc.dist_base + GICD_IGROUPR + reg_off;
		reg_mod = gic_desc.dist_base + GICD_IGRPMODR + reg_off;
		sync_wp = gic_dist_wait_rwp;
	} else {
		reg_off += percpu_id() * GICR_SIZE;
		reg = gic_desc.rdist_base + GICR_IGROUPR + reg_off;
		reg_mod = gic_desc.rdist_base + GICR_IGRPMODR + reg_off;
		sync_wp = gic_rdist_wait_uwp;
	}

	/* configure the group to Secure-group1 */
	val = ioread32(reg);
	val &= ~(1U << GIC_BIT_OFFSET(gic_num));
	iowrite32(val, reg);

	val = ioread32(reg_mod);
	val |= 1U << GIC_BIT_OFFSET(gic_num);
	iowrite32(val, reg_mod);

	sync_wp();
}

static void gic_configure_prio(unsigned int gic_num)
{
	uint32_t val = 0;
	unsigned int reg_shift = (gic_num % 4) * 8;
	unsigned int reg_off = gic_num & ~3;
	void *reg = NULL;
	void (*sync_wp)(void) = NULL;

	if (GIC_IS_SPI(gic_num)) {
		reg = gic_desc.dist_base + GICD_IPRIORITY + reg_off;
		sync_wp = gic_dist_wait_rwp;
	} else {
		reg_off += percpu_id() * GICR_SIZE;
		reg = gic_desc.rdist_base + GICR_IPRIORITY + reg_off;
		sync_wp = gic_rdist_wait_uwp;
	}

	val = ioread32(reg);
	val &= ~(GIC_SECURE_PRIORITY_MASK << reg_shift);
	val |= GICD_SECURE_PRIORITY << reg_shift;
	iowrite32(val, reg);

	sync_wp();
}

static void gic_configure_target(unsigned int gic_num, unsigned int target_cpu)
{
	uint64_t affinity = mpid_of(target_cpu);
	uint32_t reg_off = GICD_IROUTER + (gic_num * 8);

	iowrite64(affinity, gic_desc.dist_base + reg_off);
}

static inline void gic_rdist_enable(void)
{
	uint32_t val = 0;
	uint32_t in_time = 1000000;

	val = gic_read_rdist(GICR_WAKER);
	val &= ~GICR_WAKER_PROCESSORSLEEP;
	gic_write_rdist(val, GICR_WAKER);

	while (--in_time) {
		val = gic_read_rdist(GICR_WAKER);
		if (!(val & GICR_WAKER_CHILDRENASLEEP))
			break;
		udelay(1);
	}

	assert(in_time);
}

static inline void gic_rdist_disable(void)
{
	uint32_t val = 0;
	uint32_t in_time = 1000000;

	val = gic_read_rdist(GICR_WAKER);
	val |= GICR_WAKER_PROCESSORSLEEP;
	gic_write_rdist(val, GICR_WAKER);

	val = gic_read_rdist(GICR_WAKER);
	if (!(val & GICR_WAKER_PROCESSORSLEEP))
		return;

	while (--in_time) {
		val = gic_read_rdist(GICR_WAKER);
		if (val & GICR_WAKER_CHILDRENASLEEP)
			break;
		udelay(1);
	}

	assert(in_time);
}

static void gic_dist_init(void)
{
	int i = 0;
	int total = 0;
	int version = 0;

	/*
	 * interrupts not forwarded
	 */
	gic_write_dist(0, GICD_CTRL);
	gic_dist_wait_rwp();

	/*
	 * maximum number of interrupts is 32(N+1)
	 */
	total = gic_read_dist(GICD_TYPE) & 0x1F;
	total = 32 * (total + 1);
	gic_desc.total = min(total, GIC_MAX_INT);

	/*
	 * validate the version
	 */
	version = (gic_read_dist(GICD_PIDR2) >> GICD_VERSION_SHIFT)
			& GICD_VERSION_MASK;

	IMSG("%d interrupts\n", total);
	IMSG("GICDv%d\n", version);

	assert(version == gic_desc.version);

	/*
	 * Deault Route SPIs to NS-group1 (non-secure),
	 * will route to Secure-group1 when needed
	 */
	for (i = GIC_SPI_START; i < total; i += BITS_PER_INT) {
		gic_write_dist(0xFFFFFFFF, GICD_IGROUPR + GIC_REG_OFFSET(i));
		gic_write_dist(0, GICD_IGRPMODR + GIC_REG_OFFSET(i));
	}

	/*
	 * Disable All SPIs
	 * ID32-ID1019 for SPIs.
	 */
	for (i = GIC_SPI_START; i < total; i += BITS_PER_INT) {
		gic_write_dist(0xFFFFFFFF, GICD_ICACTIVER + GIC_REG_OFFSET(i));
		gic_write_dist(0xFFFFFFFF, GICD_ICENABLER + GIC_REG_OFFSET(i));
	}

	/*
	 * GICD_NSACR: NS is not allowed to access group0/Secure-group1 PPI/SPI
	 */
	gic_write_dist(0, GICD_NSACR + BYTES_PER_INT);
	for (i = GIC_SPI_START; i < total; i += 16)
		gic_write_dist(0, GICD_NSACR + ((i / 16) * BYTES_PER_INT));

	gic_dist_wait_rwp();

	/*
	 * ARE Enabled
	 */
	gic_write_dist((3 << 4), GICD_CTRL);
	gic_dist_wait_rwp();

	/*
	 * NS-group1/Secure-group1 interrupts will be forwarded
	 */
	gic_write_dist(gic_read_dist(GICD_CTRL) | 6, GICD_CTRL);
	gic_dist_wait_rwp();
}

static void gic_rdist_init(void)
{
	int version = 0;
	long mpidr = percpu_mpid();
	uint64_t typer = 0;

	/*
	 * validate the version
	 */
	version = (gic_read_rdist(GICR_PIDR2) >> GICR_VERSION_SHIFT)
			& GICR_VERSION_MASK;

	typer = gic_read_rdist64(GICR_TYPER);

	if (typer >> 32 == mpidr)
		IMSG("GICRv%d for mpid %lx @ %p\n",
			version, mpidr, RDIST_BASE);
	else
		return;

	gic_rdist_enable();

	gic_rdist_wait_uwp();

	/*
	 * handling the bank registers for each cpu interface
	 */

	/*
	 * Disable all SGI/PPI
	 *
	 * ID0-ID15 for SGIs.
	 * ID16-ID31 for PPIs.
	 */
	gic_write_rdist(0xFFFFFFFF, GICR_ICACTIVER);
	gic_write_rdist(0xFFFFFFFF, GICR_ICENABLER);

	/*
	 * Route SGI/PPI to NS-group1
	 */
	gic_write_rdist(0xFFFFFFFF, GICR_IGROUPR);
	gic_write_rdist(0, GICR_IGRPMODR);

	/*
	 * SGIs are always edge-triggered
	 * PPIs are level-sensitive
	 */
	gic_write_rdist(0xFFFFFFFF, GICR_ICFGR);
	gic_write_rdist(0, GICR_ICFGR + BYTES_PER_INT);

	/*
	 * NS is not allowed to create group0/Secure-group1 SGI
	 */
	gic_write_rdist(0, GICR_NSACR);

	gic_write_rdist(0, GICR_CTRL);
}

static void icc_version(void)
{
	int version = 0;

	if ((icc_read_sre() & 1) == 0)
		panic("GICC SystemRegister not implemented\n");

	version = read_system_reg(ID_AA64PFR0_EL1);
	version >>= PFR_GIC_VERSION_SHIFT;
	version &= PFR_GIC_VERSION_MASK;

	if (version == 1)
		IMSG("GICCv3.0 or v4.0 supported\n");
	else if (version == 3)
		IMSG("GICCv4.1 supported\n");
	else
		panic("GICC SystemRegister not implemented\n");
}

static void gic_cpuif_init(void)
{
	uint32_t activepri = 0;

	/*
	 * SRE Enabled (Bit 0)
	 */
	icc_write_sre(1);

	/*
	 * validate the version
	 */
	icc_version();

	/*
	 * Only interrupts with higher priority
	 * than the value in this register are
	 * forwarded to the processor
	 *
	 * lower value for higher priority
	 */
	icc_write_pmr(GICC_SECURE_PRIORITY);
	activepri = icc_read_ctrl();
	activepri = ((activepri >> 8) & 7) + 1;
	switch (activepri) {
	case 8:
	case 7:
		icc_write_ap1r3(0);
		icc_write_ap1r2(0);
	case 6:
		icc_write_ap1r1(0);
	case 5:
	case 4:
		icc_write_ap1r0(0);
	}

	/*
	 * EOI-Mode-1
	 */
	icc_write_ctrl(2);

	/*
	 * Enable Secure-group1 interrupts
	 */
	icc_write_igrpen1(1);
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

#define SGIR_VAL(mpidr, intid) (          \
	((unsigned long)intid << 24)        | \
	(1UL << MPIDR_AFFINITY_0(mpidr))    | \
	(MPIDR_AFFINITY_1(mpidr) << 16)     | \
	(MPIDR_AFFINITY_2(mpidr) << 32)     | \
	(MPIDR_AFFINITY_3(mpidr) << 48))

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
	int gic_num = 0;
	unsigned long flags = 0;

	gic_num = gic_softint2sgi(d->hwirq);

	if ((gic_num >= 0) && icc_read_igrpen1()) {
		local_irq_save(flags);

		unsigned long mpidr = mpid_of(cpu_id);
		unsigned long sgir = SGIR_VAL(mpidr, gic_num);
		uint32_t nsatt = gic_read_rdist(GICR_IGROUPR) & (1 << gic_num);

		/* Aff3.Aff2.Aff1.<target list> */
		if (nsatt)
			icc_write_asgi1r(sgir);
		else
			icc_write_sgi1r(sgir);

		local_irq_restore(flags);
	}
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
//	gic_rdist_disable();

	/*
	 * Disable Secure-group1 interrupts
	 */
	icc_write_igrpen1(0);
}

static void gic_resume(struct irq_controller *ic)
{
	gic_dist_init();
	gic_rdist_init();
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
	uint32_t iar = 0, gic_num = 0;

	do {
		iar = icc_read_iar1();
		gic_num = iar & ICC_IAR_INTID_MASK;

		if (gic_num >= GIC_MAX_INT)
			break;

		icc_write_dir(iar);
		irq_generic_invoke(gic_desc.controller, gic_num);
		icc_write_eoir1(iar);
	} while (1);
}

static void __init gic_parse_dts(struct device_node *dn)
{
	unsigned long base = 0;
	size_t size = 0;

	gic_desc.version = GICD_VERSION;

	of_read_property_addr_size(dn, "reg", 0, &base, &size);
	gic_desc.dist_base = iomap(base, size);
	IMSG("gic-dist %p 0x%lx, size: 0x%x\n", gic_desc.dist_base, base, (int)size);

	of_read_property_addr_size(dn, "reg", 1, &base, &size);
	gic_desc.rdist_base = iomap(base, size);
	IMSG("gic-rdist %p 0x%lx, size: 0x%x\n", gic_desc.rdist_base, base, (int)size);
}

static void gic_percpu_init(void)
{
	gic_rdist_init();
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
IRQ_CONTROLLER(gicv3, "arm,gic-v3", gic_init);
