/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Interrupt Framework for software
 * Register/Response the HW and SW Generated interrupts
 */

#ifndef _INTERRUPT_H
#define _INTERRUPT_H

#include <percpu.h>
#include <affinity.h>

/*
 * for percpu private interrupt controllers,
 * e.g. riscv clint, mips cpu intc
 */
#define IRQCTRL_PERCPU       (1 << 0)
/*
 * for shared peripheral interrupt controllers, this is the DEFAULT
 * e.g. riscv plic, SoC level interrupt controllers
 */
#define IRQCTRL_SHARED       (1 << 1)
/*
 * for COMBO: percpu private + shared peripheral interrupt controllers,
 * e.g. ARM GIC supports both SGI/PPI + SPI
 */
#define IRQCTRL_COMBO        (1 << 2)
/* for the virt softint controllers */
#define IRQCTRL_SOFTINT      (1 << 3)

struct irq_controller;

/*
 * Define the SW Generated Interrupts
 */
enum SOFTINT_ID {
	SOFTINT_RPC_CALLER = 0, /* Current system acts as REMOTE caller */
	SOFTINT_RPC_CALLEE,     /* Current system acts as REMOTE callee */
	SOFTINT_IPI,            /* Current system's LOCAL cross-processor calls */
	SOFTINT_MAX
};

typedef void (*irq_handler_t)(void *);

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
	unsigned short childcnt;

	bool disabled;
	unsigned int percpucnt[CONFIG_NR_CPUS];
};

struct irq_controller_ops {
	const char *name;

	void (*irq_enable)(struct irq_desc *desc);
	void (*irq_disable)(struct irq_desc *desc);

	bool (*irq_is_percpu)(struct irq_desc *desc);

	int (*irq_set_affinity)(struct irq_desc *desc,
			const struct cpu_affinity *affinity);

	int (*irq_parent)(struct irq_desc *desc, unsigned int *hwirq,
		irq_handler_t *handler);

	void (*irq_send)(struct irq_desc *desc, unsigned int cpu);

	void (*irq_suspend)(struct irq_desc *desc);
	void (*irq_resume)(struct irq_desc *desc);

	void (*irq_controller_suspend)(struct irq_controller *controller);
	void (*irq_controller_resume)(struct irq_controller *controller);
};

struct irq_controller {
	struct list_head node;

	/* in case of hierarchy */
	struct irq_controller *parent;

	const struct irq_controller_ops *ops;

	struct device_node *dn;

	unsigned int flags;

	unsigned int start;
	unsigned int nr_irqs;

	struct irq_desc *irqs[];
};

#define IRQ_CONTROLLER(name, compatible, initfn)              \
	static const struct of_compat_init __of_irq_##name        \
		__of_irqinit = {.compat = (compatible), .init = (void *)(initfn)}

static inline int in_interrupt(void)
{
	return thiscpu->in_interrupt;
}

struct irq_controller *irq_parent_controller(struct device_node *dn);
void irq_remove_controller(struct irq_controller *ic);

struct irq_controller *__irq_create_controller(struct device_node *dn,
	unsigned int nr_irqs, const struct irq_controller_ops *ops, unsigned int flags);

static inline struct irq_controller *irq_create_controller(struct device_node *dn,
	unsigned int nr_irqs, const struct irq_controller_ops *ops)
{
	return __irq_create_controller(dn, nr_irqs, ops, IRQCTRL_SHARED);
}

static inline struct irq_controller *irq_create_percpu_controller(
	struct device_node *dn, unsigned int nr_irqs, const struct irq_controller_ops *ops)
{
	return __irq_create_controller(dn, nr_irqs, ops, IRQCTRL_PERCPU);
}

static inline struct irq_controller *irq_create_combo_controller(
	struct device_node *dn, unsigned int nr_irqs, const struct irq_controller_ops *ops)
{
	return __irq_create_controller(dn, nr_irqs, ops, IRQCTRL_COMBO);
}

static inline struct irq_controller *irq_create_softint_controller(
	struct irq_controller *parent, unsigned int nr_irqs,
	const struct irq_controller_ops *ops)
{
	struct irq_controller *ic = NULL;

	ic = __irq_create_controller(NULL, nr_irqs, ops, IRQCTRL_SOFTINT | IRQCTRL_PERCPU);
	if (ic == NULL)
		return NULL;

	ic->parent = parent;
	return ic;
}

struct irq_desc *irq_to_desc(unsigned int irq);

void irq_enable(unsigned int irq);
void irq_disable(unsigned int irq);

int irq_register(struct irq_controller *ic,
	unsigned int hwirq, irq_handler_t handler, void *data);

int irq_unregister(unsigned int irq);

static inline int irq_of_register(struct device_node *dn,
	unsigned int hwirq, irq_handler_t handler, void *data)
{
	return irq_register(irq_parent_controller(dn), hwirq, handler, data);
}

static inline struct irq_desc *irq_to_desc_hw(
	struct irq_controller *ic, unsigned int hwirq)
{
	return ic->irqs[hwirq - ic->start];
}

void irq_generic_handle(struct irq_desc *desc);

static inline void irq_generic_invoke(
	struct irq_controller *ic, unsigned int hwirq)
{
	irq_generic_handle(irq_to_desc_hw(ic, hwirq));
}

int irq_set_affinity(unsigned int irq,
	const struct cpu_affinity *affinity);

void irq_set_root_handler(void (*root)(struct thread_ctx *));

void *irq_handler(struct thread_ctx *regs);

/*
 * For CPU Hot-Plug
 * migrating the SPIs to a live CPU
 */
void irq_migrating(void);

void irq_init(void);

/*
 * register a softint
 * return the IRQ number
 */
int register_softint(unsigned int id, irq_handler_t handler, void *data);

/*
 * Unegister a softint
 */
void unregister_softint(unsigned int id);

/*
 * Raise a softint on the
 * processor specified by @cpu_id
 */
void raise_softint(unsigned int id, unsigned int cpu_id);

#endif
