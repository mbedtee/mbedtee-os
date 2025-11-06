// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * RISCV IMSIC Interrupt-controller
 */

#include <io.h>
#include <of.h>
#include <kmap.h>
#include <trace.h>
#include <delay.h>
#include <bitops.h>
#include <tevent.h>
#include <interrupt.h>

#include <intc-aplic-imsic.h>

#define IMSIC_SGI_ID	1

#define IMSIC_PERCPU(hartid) (imsic->regs +  ((unsigned long)(hartid)) * \
	 BIT(imsic->guest_index_bits + IMSIC_PAGE_SHIFT))

struct imsic_move_affinity {
	struct imsic_desc *imsic;
	unsigned int oldcpu;
	unsigned int oldid;
	unsigned int newcpu;
	unsigned int newid;
	struct tevent tevent;
};

static void imsic_percpu_init(void);

static inline void imsic_set_csr(unsigned long reg, unsigned long val)
{
	write_csr(CSR_ISELECT, reg);
	set_csr(CSR_IREG, val);
}

static inline void imsic_clear_csr(unsigned long reg, unsigned long val)
{
	write_csr(CSR_ISELECT, reg);
	clear_csr(CSR_IREG, val);
}

static inline void imsic_write_csr(unsigned long reg, unsigned long val)
{
	write_csr(CSR_ISELECT, reg);
	write_csr(CSR_IREG, val);
}

static inline unsigned long imsic_read_csr(unsigned long reg)
{
	write_csr(CSR_ISELECT, reg);
	return read_csr(CSR_IREG);
}

static inline unsigned long imsic_read_clear_csr(
	unsigned long reg, unsigned long val)
{
	write_csr(CSR_ISELECT, reg);
	return read_clear_csr(CSR_IREG, val);
}

static bool __imsic_local_read_clear_pend(unsigned int id)
{
	unsigned long eipx = IMSIC_EIP0;
	unsigned long imask = BIT(id & (__riscv_xlen - 1));

	eipx += (id / __riscv_xlen) * (__riscv_xlen / 32);

	return !!(imsic_read_clear_csr(eipx, imask) & imask);
}

static void __imsic_local_enable(unsigned int id)
{
	unsigned long eiex = IMSIC_EIE0;

	eiex += (id / __riscv_xlen) * (__riscv_xlen / 32);
	imsic_set_csr(eiex, BIT(id & (__riscv_xlen - 1)));
}

static void __imsic_local_disable(unsigned int id)
{
	unsigned long eiex = IMSIC_EIE0;

	eiex += (id / __riscv_xlen) * (__riscv_xlen / 32);
	imsic_clear_csr(eiex, BIT(id & (__riscv_xlen - 1)));

	__imsic_local_read_clear_pend(id);
}

static void imsic_local_enable_event(struct tevent *t)
{
	__imsic_local_enable((intptr_t)t->data);
	tevent_free(t);
}

static void imsic_local_disable_event(struct tevent *t)
{
	__imsic_local_disable((intptr_t)t->data);
	tevent_free(t);
}

static void __imsic_remote_call(tevent_handler handler,
	intptr_t id, intptr_t cpu)
{
	struct tevent *t = NULL;

	while ((t = tevent_alloc(handler, (void *)id)) == NULL)
		udelay(50);

	tevent_start_on(t, &((struct timespec){0, 0}), cpu);
}

static void __imsic_irq_enable(unsigned int cpu, unsigned int id)
{
	if ((cpu == percpu_id()) || (id == IMSIC_SGI_ID))
		__imsic_local_enable(id);
	else
		__imsic_remote_call(imsic_local_enable_event, id, cpu);
}

static void __imsic_irq_disable(unsigned int cpu, unsigned int id)
{
	if ((cpu == percpu_id()) || (id == IMSIC_SGI_ID))
		__imsic_local_disable(id);
	else
		__imsic_remote_call(imsic_local_disable_event, id, cpu);
}

static void imsic_irq_enable(struct irq_desc *d)
{
	unsigned long flags = 0;
	struct imsic_desc *imsic = d->controller->data;

	spin_lock_irqsave(&imsic->sl, flags);
	__imsic_irq_enable(IMSIC_IRQ_CPU_OF(d->hwirq), IMSIC_IRQ_ID_OF(d->hwirq));
	spin_unlock_irqrestore(&imsic->sl, flags);
}

static void imsic_irq_disable(struct irq_desc *d)
{
	unsigned long flags = 0;
	struct imsic_desc *imsic = d->controller->data;

	spin_lock_irqsave(&imsic->sl, flags);
	__imsic_irq_disable(IMSIC_IRQ_CPU_OF(d->hwirq), IMSIC_IRQ_ID_OF(d->hwirq));
	spin_unlock_irqrestore(&imsic->sl, flags);
}

static int __imsic_free_irq(struct imsic_desc *imsic, unsigned int cpu,
	unsigned int id)
{
	struct imsic_percpu *priv = NULL;

	if (!id || !VALID_CPUID(cpu))
		return -EINVAL;

	priv = &imsic->pcpu_priv[cpu];
	bitmap_clear_bit(priv->bmap, id);
	priv->available++;

	return 0;
}

static int imsic_free_irq(struct imsic_desc *imsic, unsigned int irq)
{
	int ret = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&imsic->sl, flags);
	ret = __imsic_free_irq(imsic, IMSIC_IRQ_CPU_OF(irq), IMSIC_IRQ_ID_OF(irq));
	spin_unlock_irqrestore(&imsic->sl, flags);

	return ret;
}

static unsigned int imsic_suitable_cpu(struct imsic_desc *imsic,
	const struct cpu_affinity *affinity)
{
	unsigned int available = 0, _cpu = 0;
	struct imsic_percpu *priv = NULL;
	struct cpu_affinity tmp;
	unsigned int cpu = -1;

	cpu_affinity_and(&tmp, affinity, cpus_online);

	for_each_affinity_cpu(_cpu, &tmp) {
		priv = &imsic->pcpu_priv[_cpu];

		if (priv->available <= available)
			continue;

		cpu = _cpu;
		available = priv->available;
	}

	return cpu;
}

static int __imsic_alloc_irq(struct imsic_desc *imsic,
	unsigned int *irq, unsigned int cpu)
{
	unsigned int id = 0;
	struct imsic_percpu *priv = NULL;

	priv = &imsic->pcpu_priv[cpu];
	id = bitmap_next_zero(priv->bmap, imsic->max + 1, priv->next);
	if (id > imsic->max) {
		id = bitmap_next_zero(priv->bmap, imsic->max + 1, 0);
		if (id > imsic->max)
			return -ENOSPC;
	}

	bitmap_set_bit(priv->bmap, id);
	priv->available--;

	priv->next = id + 1;

	*irq = IMSIC_IRQ_OF(cpu, id);

	return 0;
}

static int imsic_alloc_irq(struct imsic_desc *imsic,
	unsigned int *irq, const struct cpu_affinity *affinity)
{
	int ret = 0;
	unsigned int cpu = -1;
	unsigned long flags = 0;

	spin_lock_irqsave(&imsic->sl, flags);

	cpu = imsic_suitable_cpu(imsic, affinity);
	if (!VALID_CPUID(cpu)) {
		ret = -ENOSPC;
		goto out;
	}

	ret = __imsic_alloc_irq(imsic, irq, cpu);

out:
	spin_unlock_irqrestore(&imsic->sl, flags);
	return ret;
}

static void imsic_irq_handler(void *data)
{
	unsigned int irq = 0, cpu = percpu_id();
	struct irq_controller *ic = data;
	struct imsic_desc *imsic = ic->data;

	while ((irq = swap_csr(CSR_TOPEI, 0))) {
		if ((irq = irq >> 16) != IMSIC_SGI_ID)
			irq = IMSIC_IRQ_OF(cpu, irq);
		irq_generic_invoke(ic, irq);
	}
}

static void __imsic_local_sync_old(
	struct imsic_desc *imsic,
	unsigned int oldcpu, unsigned int oldid,
	unsigned int newcpu, unsigned int newid)
{
	__imsic_local_disable(oldid);

	if (__imsic_local_read_clear_pend(oldid))
		iowrite32(newid, IMSIC_PERCPU(hartid_of(newcpu)));

	__imsic_free_irq(imsic, oldcpu, oldid);

	irq_clear_desc_hwirq(imsic->controller, IMSIC_IRQ_OF(oldcpu, oldid));
}

static void __imsic_local_sync_for_old_event(struct tevent *t)
{
	struct imsic_move_affinity *mov = t->data;
	struct imsic_desc *imsic = mov->imsic;

	spin_lock(&imsic->sl);

	__imsic_local_sync_old(imsic, mov->oldcpu,
		mov->oldid, mov->newcpu, mov->newid);

	spin_unlock(&imsic->sl);

	spin_lock(&t->lock);
	kfree(mov);
}

static void __imsic_sync_affinity_old(
	struct imsic_desc *imsic,
	unsigned int oldcpu, unsigned int oldid,
	unsigned int newcpu, unsigned int newid)
{
	struct imsic_move_affinity *mov = NULL;

	if (!VALID_CPUID(oldcpu))
		return;

	if (oldcpu == percpu_id()) {
		__imsic_local_sync_old(imsic, oldcpu, oldid, newcpu, newid);
		return;
	}

	while ((mov = kmalloc(sizeof(*mov))) == NULL)
		udelay(50);

	mov->imsic = imsic;
	mov->oldcpu = oldcpu;
	mov->oldid = oldid;
	mov->newcpu = newcpu;
	mov->newid = newid;

	tevent_init(&mov->tevent, __imsic_local_sync_for_old_event, mov);

	tevent_start_on(&mov->tevent, &(struct timespec){0, 0}, oldcpu);
}

void imsic_post_set_affinity(struct irq_desc *d,
	unsigned int oldcpu, unsigned int oldid)
{
	unsigned long flags = 0;
	unsigned int newid = 0;
	unsigned int newirq = d->hwirq;
	struct imsic_desc *imsic = d->controller->data;
	unsigned int newcpu = IMSIC_IRQ_CPU_OF(newirq);

	if (oldcpu == newcpu || oldid == 0)
		return;

	spin_lock_irqsave(&imsic->sl, flags);

	if (irq_is_enabled(d)) {
		newid = IMSIC_IRQ_ID_OF(newirq);
		__imsic_irq_enable(newcpu, newid);
		__imsic_sync_affinity_old(imsic, oldcpu, oldid,
				newcpu, newid);
	} else {
		__imsic_free_irq(imsic, oldcpu, oldid);
		irq_clear_desc_hwirq(imsic->controller, IMSIC_IRQ_OF(oldcpu, oldid));
	}

	spin_unlock_irqrestore(&imsic->sl, flags);
}

static int imsic_set_affinity(struct irq_desc *d,
	const struct cpu_affinity *affinity, bool force)
{
	unsigned long flags = 0;
	struct imsic_desc *imsic = d->controller->data;
	unsigned int newcpu = 0, newirq = 0, ret = 0;
	unsigned int oldcpu = IMSIC_IRQ_CPU_OF(d->hwirq);

	/* just update affinity, no need to update HW setting */
	if (cpu_affinity_isset(affinity, oldcpu)) {
		cpu_affinity_copy(d->affinity, affinity);
		return 0;
	}

	spin_lock_irqsave(&imsic->sl, flags);

	newcpu = imsic_suitable_cpu(imsic, affinity);
	if (!VALID_CPUID(newcpu)) {
		if (force)
			newcpu = percpu_id();
		else {
			ret = -EINVAL;
			goto out;
		}
	}

	if (oldcpu == newcpu) {
		cpu_affinity_copy(d->affinity, affinity);
		goto out;
	}

	__imsic_alloc_irq(imsic, &newirq, newcpu);

	irq_update_desc_hwirq(d, newirq);

	cpu_affinity_copy(d->affinity, affinity);

out:
	spin_unlock_irqrestore(&imsic->sl, flags);
	return ret;
}

/*
 * Send a softint (SGI) to the
 * processor specified by @cpu
 */
static void imsic_softint_raise(struct irq_desc *d,
	unsigned int cpu)
{
	unsigned long hartid = 0;
	struct imsic_desc *imsic = d->controller->data;

	hartid = VALID_CPUID(cpu) ? hartid_of(cpu) : cpu;

	iowrite32(d->hwirq, IMSIC_PERCPU(hartid));
}

static int imsic_parent_alloc(struct irq_desc *d,
	unsigned int *hwirq, unsigned int *type)
{
	int ret = 0;
	struct imsic_desc *imsic = d->controller->data;

	ret = imsic_alloc_irq(imsic, hwirq, cpus_online);
	if (ret != 0) {
		EMSG("imsic_alloc_irq failed %d\n", ret);
		return ret;
	}

	*type = 0;

	return 0;
}

static int imsic_parent_free(struct irq_desc *d)
{
	struct imsic_desc *imsic = d->controller->data;

	return imsic_free_irq(imsic, d->hwirq);
}

static void imsic_alloc_percpu(struct imsic_desc *d)
{
	int cpu;
	struct imsic_percpu *priv = NULL;

	for_each_possible_cpu(cpu) {
		priv = &d->pcpu_priv[cpu];

		priv->bmap = bitmap_zalloc(d->max + 1);
		if (priv->bmap == NULL)
			goto cleanup;

		priv->next = 1;
		priv->available = d->max - 1;
		bitmap_set_bit(priv->bmap, 0); /* never implemented */
		bitmap_set_bit(priv->bmap, IMSIC_SGI_ID); /* Reserved for SGI */
	}

	return;

cleanup:
	for_each_possible_cpu(cpu) {
		priv = &d->pcpu_priv[cpu];
		bitmap_free(priv->bmap);
	}
}

static int __init imsic_parse_dts(struct imsic_desc *d, struct device_node *dn)
{
	int ret = -1;
	unsigned long addr = 0;
	size_t size = 0;

	ret = of_parse_io_resource(dn, IS_ENABLED(CONFIG_RISCV_S_MODE), &addr, &size);
	if (ret)
		return ret;

	d->phys_addr = addr;

	ret = of_property_read_u32(dn, "imsic,guest-index-bits", &d->guest_index_bits);
	if (ret || !IS_ENABLED(CONFIG_RISCV_S_MODE))
		d->guest_index_bits = 0;

	ret = of_property_read_u32(dn, "imsic,hart-index-bits", &d->hart_index_bits);
	if (ret)
		d->hart_index_bits = log2of(size >> (IMSIC_PAGE_SHIFT + d->guest_index_bits));

	if (size < BIT(IMSIC_PAGE_SHIFT + d->guest_index_bits + d->hart_index_bits))
		return -EINVAL;

	if (addr & (BIT(IMSIC_PAGE_SHIFT + d->guest_index_bits + d->hart_index_bits) - 1))
		return -EINVAL;

	ret = of_irq_parse_max(dn, &d->max);
	if (ret || (d->max >= IMSIC_MAX_INT))
		return -EINVAL;

	d->regs = iomap(addr, size);

	IMSG("init %s %d irqs\n", dn->id.name, d->max);

	IMSG("guest-index-bits %d hart-index-bits %d\n",
			d->guest_index_bits, d->hart_index_bits);

	return 0;
}

static void imsic_resume(struct irq_controller *ic)
{
	imsic_percpu_init();
}


static const struct irq_controller_ops imsic_intc_ops = {
	.name = "riscv,imsic",
	.irq_enable	= imsic_irq_enable,
	.irq_disable = imsic_irq_disable,
	.irq_parent_alloc = imsic_parent_alloc,
	.irq_parent_free = imsic_parent_free,
	.irq_set_affinity = imsic_set_affinity,

	.irq_send = imsic_softint_raise,

	.irq_controller_resume = imsic_resume
};


static void imsic_percpu_init(void)
{
	struct irq_controller *ic = NULL;

	/*
	 * currently there is only one imsic in one RISCV system.
	 * if there are multi-imsic in one RISCV system in the future,
	 * add a irq_for_each_matching_controller() to handle them all.
	 */
	ic = irq_matching_ops_controller(&imsic_intc_ops);

	/* 1 = interrupt delivery is enabled for this hart */
	imsic_write_csr(IMSIC_EIDELIVERY, 1);

	/*
	 * set the threshold to 0 - means to delivery all enabled intsrc to this hart
	 */
	imsic_write_csr(IMSIC_EITHRESHOLD, 0);

	/* percpu link(register/enable) the imsic with its parent controller */
	irq_chained_register(ic, IS_ENABLED(CONFIG_RISCV_S_MODE), imsic_irq_handler, ic);
}
PERCPU_INIT_ROOT(imsic_percpu_init);

static void __init imsic_intc_init(struct device_node *dn)
{
	struct imsic_desc *imsic = NULL;
	struct irq_controller *ic = NULL;

	imsic = kmalloc(sizeof(*imsic));
	if (imsic == NULL)
		return;

	if (imsic_parse_dts(imsic, dn) != 0)
		return;

	imsic_alloc_percpu(imsic);

	/*
	 * create an interrupt controller, it also will be chained to its
	 * parent controller later at percpu routine -> imsic_percpu_init()
	 */
	ic = irq_create_controller(dn, cpu_max_possible_num() *
			(imsic->max + 1), &imsic_intc_ops, imsic);

	imsic->controller = ic;

	/* IMSIC provides one SGI source for softint framework */
	softint_init(ic, &(unsigned int){IMSIC_SGI_ID}, 1);
}
IRQ_CONTROLLER(imsic, "riscv,imsic", imsic_intc_init);
