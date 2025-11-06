/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Interrupt Framework for software
 * Register/Response the HW and SW Generated interrupts
 */

#ifndef _INTERRUPT_H
#define _INTERRUPT_H

#include <affinity.h>

/*
 * for percpu private interrupt controllers,
 * e.g. riscv clint, mips cpu intc
 */
#define IRQCTRL_PERCPU			(1 << 0)
/*
 * for shared peripheral interrupt controllers, this is the DEFAULT
 * e.g. riscv plic, SoC level interrupt controllers
 */
#define IRQCTRL_SHARED			(1 << 1)
/*
 * for COMBO: percpu private + shared peripheral interrupt controllers,
 * e.g. ARM GIC supports both SGI/PPI + SPI
 */
#define IRQCTRL_COMBO			(1 << 2)


/*
 * Define the interrupt source's assert types
 */
#define IRQ_TYPE_EDGE_RISING	(1 << 0)
#define IRQ_TYPE_EDGE_FALLING	(1 << 1)
#define IRQ_TYPE_LEVEL_HIGH		(1 << 2)
#define IRQ_TYPE_LEVEL_LOW		(1 << 3)
#define IRQ_TYPE_MASK			((1 << 4) - 1)
/*
 * Define the interrupt flags, share variable with IRQ_TYPE_#
 */
#define IRQ_ENABLED				(1 << 8)
#define IRQ_IS_CONTROLLER		(1 << 9)

/*
 * Define the SW Generated Interrupts (Softint/SGI)
 */
#define SOFTINT_RPC_CALLER	0 /* Current system acts as REMOTE caller */
#define SOFTINT_RPC_CALLEE	1 /* Current system acts as REMOTE callee */
#define SOFTINT_IPI			2 /* Current system's LOCAL inter-processor calls */
#define SOFTINT_MAX			3

struct irq_controller;

typedef void (*irq_handler_t)(void *);
typedef int (*irq_softint_handler_t)(void *);
typedef void (*irq_root_handler_t)(struct irq_controller *, struct thread_ctx *);

struct irq_desc {
	unsigned int irq;
	unsigned int hwirq;
	irq_handler_t handler;

	void *data;

	struct irq_controller *controller;

	struct cpu_affinity affinity[1];

	/* rb-node @ OS global tree */
	struct rb_node rbnode;

	struct irq_desc *parent;

	/* how many child exist ? */
	unsigned int childcnt;

	unsigned int flags;
	unsigned int percpucnt[CONFIG_NR_CPUS];
};

struct irq_controller_ops {
	const char *name;

	void (*irq_enable)(struct irq_desc *desc);
	void (*irq_disable)(struct irq_desc *desc);

	bool (*irq_is_percpu)(struct irq_desc *desc);

	int (*irq_set_affinity)(struct irq_desc *desc,
			const struct cpu_affinity *affinity, bool force);

	int (*irq_set_type)(struct irq_desc *desc, unsigned int type);

	int (*irq_parent_alloc)(struct irq_desc *desc, unsigned int *hwirq,
		unsigned int *type);
	int (*irq_parent_free)(struct irq_desc *desc);
	int (*irq_translate)(struct irq_desc *desc, unsigned int *hwirq,
		unsigned int *type);

	void (*irq_send)(struct irq_desc *desc, unsigned int cpu);

	void (*irq_suspend)(struct irq_desc *desc);
	void (*irq_resume)(struct irq_desc *desc);

	void (*irq_controller_suspend)(struct irq_controller *controller);
	void (*irq_controller_resume)(struct irq_controller *controller);
};

struct irq_controller {
	struct list_head node;

	const struct irq_controller_ops *ops;

	/* controller's node in the device tree */
	struct device_node *dn;

	/* controller's private data */
	void *data;

	/* in case of hierarchy */
	struct irq_controller *parent;
	/* index of the #interrupts=<0 1 2 ...> property in DTS */
	unsigned int irqidx;

	/* number of IRQs in this controller */
	unsigned int nr_irqs;

	unsigned char flags;

	/* IRQs' linear mapping */
	struct irq_desc **irqs;
};

#define IRQ_CONTROLLER(name, compatible, initfn)			  \
	static const struct of_compat_init __of_irq_##name		  \
		__of_irqinit = {.compat = (compatible), .init = (void *)(initfn)}

static inline int in_interrupt(void)
{
	return thiscpu->in_interrupt;
}

/*
 * Find the first matching controller
 */
struct irq_controller *irq_parent_controller(struct device_node *dn);
struct irq_controller *irq_matching_controller(const struct device_node *dn);
struct irq_controller *irq_matching_ops_controller(
	const struct irq_controller_ops *ops);

/*
 * caller must ensure all the IRQs in this controller are unregistered
 */
void irq_remove_controller(struct irq_controller *ic);

struct irq_controller *__irq_create_controller(
	struct device_node *dn, unsigned int nr_irqs,
	const struct irq_controller_ops *ops, unsigned int flags);

static inline struct irq_controller *_irq_create_controller(
	struct device_node *dn, unsigned int nr_irqs,
	const struct irq_controller_ops *ops, unsigned int flags, void *data)
{
	struct irq_controller *ic = NULL;

	ic = __irq_create_controller(dn, nr_irqs, ops, flags);
	if (ic == NULL)
		return NULL;

	ic->data = data;
	return ic;
}

static inline struct irq_controller *irq_create_controller(
	struct device_node *dn, unsigned int nr_irqs,
	const struct irq_controller_ops *ops, void *data)
{
	return _irq_create_controller(dn, nr_irqs, ops, IRQCTRL_SHARED, data);
}

static inline struct irq_controller *irq_create_percpu_controller(
	struct device_node *dn, unsigned int nr_irqs,
	const struct irq_controller_ops *ops, void *data)
{
	return _irq_create_controller(dn, nr_irqs, ops, IRQCTRL_PERCPU, data);
}

static inline struct irq_controller *irq_create_combo_controller(
	struct device_node *dn, unsigned int nr_irqs,
	const struct irq_controller_ops *ops, void *data)
{
	return _irq_create_controller(dn, nr_irqs, ops, IRQCTRL_COMBO, data);
}

struct irq_desc *irq_to_desc(unsigned int irq);

void irq_enable(unsigned int irq);
void irq_disable(unsigned int irq);

int irq_unregister(unsigned int irq);

/*
 * register/enable the #hwirq in its parent interrupt controller
 * #parent: hwirq's parent interrupt controller
 *
 * #hwirq: interrupt number in its parent interrupt controller
 *
 * return the system-wide IRQ number on success
 */
int irq_register_simple(struct irq_controller *parent,
	unsigned int hwirq, irq_handler_t handler, void *data);

/*
 * register/enable the device's interrupt in its #interrupt-parent
 *
 * #dn: device node in DTS which contains the interrupt information
 * #idx: device may have multi-interrupts in DTS, #idx specifies the ID
 * e.g. specifies the index of the "interrupts = <0 1 2 ...>" property
 *
 * return the system-wide IRQ number on success
 */
int irq_indexed_register(struct device_node *dn,
	unsigned int idx, irq_handler_t handler, void *data);

/*
 * register/enable the device's interrupt in its #interrupt-parent
 *
 * #dn: device node in DTS which contains the interrupt information
 *
 * return the system-wide IRQ number on success
 */
static inline int irq_register(struct device_node *dn,
	irq_handler_t handler, void *data)
{
	return irq_indexed_register(dn, 0, handler, data);
}

/*
 * Chained a intermediate controller into the hierarchy
 *
 * register/enable the controller's interrupt in its #interrupt-parent
 *
 * #idx: controller may have multi-interrupts in DTS, #idx specifies the ID
 * e.g. specifies the index of the "interrupts = <0 1 2 ...>" property
 *
 * return the system-wide IRQ number on success
 */
static inline int irq_chained_register(struct irq_controller *curr,
	unsigned int idx, irq_handler_t handler, void *data)
{
	int ret = irq_indexed_register(curr->dn, idx, handler, data);

	curr->irqidx = idx;

	return ret;
}

/*
 * The __irq_lock shall be held already.
 * Update the hwirq type in a irq_desc.
 */
static inline void irq_update_desc_type(struct irq_desc *d,
	unsigned int type)
{
	d->flags |= type & IRQ_TYPE_MASK;
}

/*
 * The __irq_lock shall be held already.
 * Update the hwirq number in a irq_desc.
 */
static inline void irq_update_desc_hwirq(struct irq_desc *d,
	unsigned int hwirq_new)
{
	struct irq_controller *ic = d->controller;

	d->hwirq = hwirq_new;

	if (hwirq_new < ic->nr_irqs)
		ic->irqs[hwirq_new] = d;
}

/*
 * The __irq_lock shall be held already.
 * Clear the hwirq-irq_desc's pointer in the controller's linear array.
 */
static inline void irq_clear_desc_hwirq(
	struct irq_controller *ic, unsigned int hwirq)
{
	if (hwirq < ic->nr_irqs)
		ic->irqs[hwirq] = NULL;
}

static inline struct irq_desc *irq_to_desc_hw(
	struct irq_controller *ic, unsigned int hwirq)
{
	if (hwirq < ic->nr_irqs)
		return ic->irqs[hwirq];

	return NULL;
}

static inline bool irq_is_enabled(struct irq_desc *d)
{
	return !!(d->flags & IRQ_ENABLED);
}

static inline void irq_set_enable(struct irq_desc *d)
{
	d->flags |= IRQ_ENABLED;
}

static inline void irq_clear_enable(struct irq_desc *d)
{
	d->flags &= ~(IRQ_ENABLED);
}

void irq_generic_handle(struct irq_desc *d);

static inline void irq_generic_invoke(
	struct irq_controller *ic, unsigned int hwirq)
{
	irq_generic_handle(irq_to_desc_hw(ic, hwirq));
}

int irq_set_affinity(unsigned int irq,
	const struct cpu_affinity *affinity);

void irq_set_root_handler(irq_root_handler_t handler);

void *irq_handler(struct thread_ctx *regs);

/*
 * For CPU Hot-Plug
 * migrating the SPIs to a live CPU
 */
void irq_migrating(void);

/*
 * parse all the #interrupt-controller in DTS, probe them all.
 */
void irq_init(void);

/*
 * caller should be the interrupt controller,
 * to provide the HW interrupt sources for the softint
 */
void softint_init(struct irq_controller *ic,
	unsigned int *hwirqs, unsigned int nr_irqs);

/*
 * Register the softint @ id
 * return 0 on success
 */
int softint_register(unsigned int id,
	irq_softint_handler_t handler, void *data);

/*
 * Unregister the softint
 */
void softint_unregister(unsigned int id);

/*
 * Raise a softint on the
 * processor specified by @cpu (except RPC_CALLER)
 */
void softint_raise(unsigned int id, unsigned int cpu);

#endif
