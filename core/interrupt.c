// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Interrupt Framework for software
 * Register/Response the HW and SW Generated interrupts
 */

#include <of.h>
#include <io.h>
#include <cpu.h>
#include <trace.h>
#include <bitops.h>
#include <rbtree.h>
#include <kmalloc.h>
#include <spinlock.h>
#include <interrupt.h>

/* Max. IRQs within whole OS */
#define IRQ_MAX (2048)

/* support multi-interrupt-controllers */
static LIST_HEAD(__controllers);
static SPIN_LOCK(__controllers_lock);

/* lock for IRQ-IDA and Red-Black-Tree */
static SPIN_LOCK(__irq_lock);
static DECLARE_BITMAP(__irqida, IRQ_MAX);
static unsigned int __irq_idnext = 1;
static struct rb_node *__irq_rbroot;

static irq_root_handler_t root_handler;

#define IRQ_IS_PERCPU(ctrl, desc) (((ctrl)->flags & IRQCTRL_PERCPU) || \
	((ctrl)->ops->irq_is_percpu && (ctrl)->ops->irq_is_percpu(desc)))

struct irq_controller *irq_matching_controller(
	const struct device_node *dn)
{
	struct irq_controller *ic = NULL, *ret = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&__controllers_lock, flags);
	list_for_each_entry_reverse(ic, &__controllers, node) {
		if (dn == ic->dn) {
			ret = ic;
			break;
		}
	}
	spin_unlock_irqrestore(&__controllers_lock, flags);

	return ret;
}

struct irq_controller *irq_matching_ops_controller(
	const struct irq_controller_ops *ops)
{
	struct irq_controller *ic = NULL, *ret = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&__controllers_lock, flags);
	list_for_each_entry(ic, &__controllers, node) {
		if (ops == ic->ops) {
			ret = ic;
			break;
		}
	}
	spin_unlock_irqrestore(&__controllers_lock, flags);

	return ret;
}

struct irq_controller *irq_parent_controller(struct device_node *dn)
{
	struct irq_controller *ic = NULL, *ret = NULL;
	struct device_node *parent = of_irq_find_parent(dn);
	unsigned long flags = 0;

	if (parent == NULL)
		return NULL;

	spin_lock_irqsave(&__controllers_lock, flags);
	list_for_each_entry(ic, &__controllers, node) {
		if (parent == ic->dn) {
			ret = ic;
			break;
		}
	}
	spin_unlock_irqrestore(&__controllers_lock, flags);

	return ret;
}

static inline intptr_t __irq_rbfind_cmp(
	const void *irq, const struct rb_node *ref)
{
	return (intptr_t)irq - rb_entry_of(ref, struct irq_desc, rbnode)->irq;
}

static struct irq_desc *__irq_to_desc(unsigned int irq)
{
	return rb_entry(rb_find((void *)(intptr_t)irq,
		__irq_rbroot, __irq_rbfind_cmp), struct irq_desc, rbnode);
}

struct irq_desc *irq_to_desc(unsigned int irq)
{
	unsigned long flags = 0;
	struct irq_desc *desc = NULL;

	spin_lock_irqsave(&__irq_lock, flags);
	desc = __irq_to_desc(irq);
	spin_unlock_irqrestore(&__irq_lock, flags);

	return desc;
}

static inline intptr_t __irq_rbadd_cmp(
	const struct rb_node *n,
	const struct rb_node *ref)
{
	return (intptr_t)rb_entry_of(n, struct irq_desc, rbnode)->irq -
		(intptr_t)rb_entry_of(ref, struct irq_desc, rbnode)->irq;
}

static int __irq_free(struct irq_desc *d)
{
	unsigned int irq = d->irq;
	unsigned int hwirq = d->hwirq;
	struct irq_controller *ic = d->controller;
	const char *name = ic->dn ? ic->dn->id.name : ic->ops->name;

	if (d->childcnt) {
		WMSG("irq %d hwirq %d @ %s - %d child inuse\n",
			irq, hwirq, name, d->childcnt);
		return -EBUSY;
	}

	if (IRQ_IS_PERCPU(ic, d)) {
		cpu_affinity_clear(d->affinity, percpu_id());
		if (!cpu_affinity_empty(d->affinity)) {
			WMSG("irq %d hwirq %d @ %s - cpumap(%lx) inuse\n",
				irq, hwirq, name, ioreadl(d->affinity));
			return -EBUSY;
		}
	}

	/* unlink the irq desc with hwirq @ controller */
	if (hwirq < ic->nr_irqs)
		ic->irqs[hwirq] = NULL;

	IMSG("irq %d hwirq %d @ %s\n", irq, hwirq, name);

	if (ic->ops->irq_disable && irq_is_enabled(d))
		ic->ops->irq_disable(d);

	if (ic->ops->irq_parent_free)
		ic->ops->irq_parent_free(d);

	/* del the irq desc from OS global rb-tree */
	rb_del(&d->rbnode, &__irq_rbroot);

	bitmap_clear_bit(__irqida, irq);

	kfree(d);

	return 0;
}

static int __irq_unregister(struct irq_desc *d)
{
	int ret = 0;
	struct irq_desc *dparent = NULL;

	dparent = d->parent;

	/* free the child */
	ret = __irq_free(d);
	if (ret)
		return ret;

	/* parent present ? */
	while ((d = dparent) != NULL) {
		dparent = d->parent;
		d->childcnt--;

		/* skip controller's irq */
		if (d->flags & IRQ_IS_CONTROLLER)
			break;
		__irq_free(d);
	}

	return ret;
}

int irq_unregister(unsigned int irq)
{
	int ret = 0;
	unsigned long flags = 0;
	struct irq_desc *d = NULL;

	spin_lock_irqsave(&__irq_lock, flags);

	d = __irq_to_desc(irq);
	if (d == NULL) {
		ret = -EINVAL;
		goto out;
	}

	ret = __irq_unregister(d);

out:
	spin_unlock_irqrestore(&__irq_lock, flags);
	return ret;
}

static struct irq_desc *__irq_alloc_desc(void)
{
	unsigned int irq = 0;
	struct irq_desc *desc = NULL;

	desc = kzalloc(sizeof(struct irq_desc));
	if (desc == NULL)
		return NULL;

	irq = bitmap_next_zero(__irqida, IRQ_MAX, __irq_idnext);
	if (irq == IRQ_MAX)
		irq = bitmap_next_zero(__irqida, IRQ_MAX, 1);

	if (irq == IRQ_MAX) {
		kfree(desc);
		return NULL;
	}

	__irq_idnext = irq + 1;
	bitmap_set_bit(__irqida, irq);

	desc->irq = irq;
	return desc;
}

static struct irq_desc *__irq_alloc(	struct irq_controller *ic,
	unsigned int hwirq, unsigned int type,
	irq_handler_t handler, void *data)
{
	struct irq_desc *d = NULL;

	d = __irq_alloc_desc();
	if (d == NULL)
		return NULL;

	d->hwirq = hwirq;
	d->controller = ic;
	d->handler = handler;
	d->data = data;
	d->flags = type;

	if (!IRQ_IS_PERCPU(ic, d))
		cpu_affinity_fill(d->affinity);

	/* link the irq desc with hwirq @ controller - when linear mapping */
	if (hwirq < ic->nr_irqs)
		ic->irqs[hwirq] = d;
	/* add the irq desc to OS global rb-tree */
	rb_add(&d->rbnode, &__irq_rbroot, __irq_rbadd_cmp);

	return d;
}

static void __irq_enable(struct irq_controller *ic,
	struct irq_desc *d, bool force_affinity)
{
	if (d->handler == NULL)
		return;

	if (d->parent)
		__irq_enable(d->parent->controller, d->parent, false);

	if (IRQ_IS_PERCPU(ic, d))
		cpu_affinity_set(d->affinity, percpu_id());
	else {
		if (ic->ops->irq_set_affinity)
			ic->ops->irq_set_affinity(d, d->affinity, force_affinity);

		if (ic->ops->irq_set_type)
			ic->ops->irq_set_type(d, d->flags & IRQ_TYPE_MASK);
	}

	if (ic->ops->irq_enable) {
		ic->ops->irq_enable(d);
		irq_set_enable(d);
	}
}

static int __irq_register(struct irq_controller *ic,
	unsigned int hwirq, unsigned int type,
	irq_handler_t handler, void *data)
{
	int ret = 0, depth = 0;
	struct irq_desc *d = NULL;
	struct irq_desc *dchild = NULL;
	struct irq_desc *dparent = NULL;
	struct irq_controller *curr = NULL;
	struct irq_controller *parent = NULL;

	/* only check the linear mapping controller */
	if (ic->nr_irqs && hwirq >= ic->nr_irqs)
		return -EINVAL;

	/* already registered */
	d = irq_to_desc_hw(ic, hwirq);
	if (d != NULL)
		goto reenable;

	d = __irq_alloc(ic, hwirq, type, handler, data);
	if (d == NULL)
		return -ENOMEM;

	dchild = d;
	curr = ic;
	while ((parent = curr->parent) != NULL) {
		/*
		 * Need to get the parent-irq-num @ parent controller.
		 *
		 * irq_parent_alloc and irq_translate obviously can't be coexisted
		 *
		 * irq_parent_alloc() has the higher priority, alloc the irq from
		 * parent controller means the current controller is unable to get
		 * the parent-irq-num directly by implementing the irq_translate().
		 */
		if (parent->ops->irq_parent_alloc) {
			dparent = __irq_alloc(parent, -1, 0, handler, data);
			if (dparent == NULL) {
				ret = -ENOMEM;
				goto out;
			}
			ret = parent->ops->irq_parent_alloc(dparent, &hwirq, &type);
			if (ret != 0)
				goto out;

			irq_update_desc_hwirq(dparent, hwirq);
			irq_update_desc_type(dparent, type);
		} else {
			/*
			 * Current controller is able to translate the parent-irq-num ?
			 */
			if (curr->ops->irq_translate)
				ret = curr->ops->irq_translate(dchild, &hwirq, &type);
			else {
				ret = of_irq_parse_one(curr->dn, curr->irqidx, &hwirq, &type);
				if (ret) {
					EMSG("Unable to parse interrupt idx %d @ %s\n",
							curr->irqidx, curr->dn->id.name);
					EMSG("wrong chained setting @ %s\n", curr->ops->name);
				}
			}
			if (ret != 0)
				goto out;

			/* alreay registered ? */
			dparent = irq_to_desc_hw(parent, hwirq);
			if (dparent == NULL) {
				dparent = __irq_alloc(parent, hwirq, type, handler, data);
				if (dparent == NULL) {
					ret = -ENOMEM;
					goto out;
				}
			}
		}

		depth++;
		curr = parent;
		dparent->childcnt++;
		dchild->parent = dparent;
		dchild = dchild->parent;
	}

reenable:
	__irq_enable(ic, d, true);

out:
	if (ret != 0) {
		dparent = d->parent;
		__irq_free(d);

		/* free the parents we just allocated */
		while (((d = dparent) != NULL) && depth) {
			depth--;
			dparent = d->parent;
			d->childcnt--;
			__irq_free(d);
		}

		return ret;
	}
	return d->irq;
}

int irq_indexed_register(struct device_node *dn,
	unsigned int idx, irq_handler_t handler, void *data)
{
	int ret = -1;
	unsigned long flags = 0;
	unsigned int hwirq = 0, type = 0;
	struct irq_controller *ic = irq_parent_controller(dn);

	if (ic == NULL)
		return -EINVAL;

	ret = of_irq_parse_one(dn, idx, &hwirq, &type);
	if (ret) {
		EMSG("Unable to parse interrupt idx %d @ %s\n",
				idx, dn->id.name);
		return ret;
	}

	IMSG("%d of %s -> %s\n", hwirq, dn->id.name, ic->ops->name);

	if (irq_matching_controller(dn))
		type |= IRQ_IS_CONTROLLER;

	spin_lock_irqsave(&__irq_lock, flags);

	ret = __irq_register(ic, hwirq, type, handler, data);

	spin_unlock_irqrestore(&__irq_lock, flags);

	return ret;
}

int irq_register_simple(struct irq_controller *ic,
	unsigned int hwirq, irq_handler_t handler, void *data)
{
	int ret = -1;
	unsigned long flags = 0;

	if (ic == NULL)
		ic = list_first_entry_or_null(&__controllers,
			struct irq_controller, node);

	if (ic == NULL)
		return -EINVAL;

	IMSG("%d -> %s\n", hwirq, ic->ops->name);

	spin_lock_irqsave(&__irq_lock, flags);

	ret = __irq_register(ic, hwirq, 0, handler, data);

	spin_unlock_irqrestore(&__irq_lock, flags);

	return ret;
}

struct irq_controller *__irq_create_controller(struct device_node *dn,
	unsigned int nr_irqs, const struct irq_controller_ops *ops, unsigned int iflag)
{
	struct irq_controller *ic = NULL;
	unsigned long flags = 0;

	if (nr_irqs > IRQ_MAX)
		return NULL;

	ic = kzalloc(sizeof(struct irq_controller));
	if (ic == NULL)
		return NULL;

	ic->dn = dn;
	ic->ops = ops;
	ic->flags = iflag;
	ic->irqidx = -1u;
	ic->nr_irqs = nr_irqs;
	ic->parent = irq_parent_controller(dn);
	if (nr_irqs) {
		ic->irqs = kzalloc(nr_irqs * sizeof(struct irq_desc *));
		if (ic->irqs == NULL) {
			kfree(ic);
			return NULL;
		}
	}

	spin_lock_irqsave(&__controllers_lock, flags);
	list_add_tail(&ic->node, &__controllers);
	spin_unlock_irqrestore(&__controllers_lock, flags);

	return ic;
}

void irq_remove_controller(struct irq_controller *ic)
{
	unsigned long flags = 0, i = 0;
	struct irq_desc *d = NULL;

	spin_lock_irqsave(&__controllers_lock, flags);
	list_del(&ic->node);
	spin_unlock_irqrestore(&__controllers_lock, flags);

	spin_lock_irqsave(&__irq_lock, flags);

	for (i = 0; i < ic->nr_irqs; i++) {
		d = ic->irqs[i];
		if (d != NULL) {
			WMSG("irq %d hwirq %d @ %s still inuse\n",
				d->irq, d->hwirq, ic->dn ?
				ic->dn->id.name : ic->ops->name);
			__irq_unregister(d);/* try to remove */
		}
	}

	spin_unlock_irqrestore(&__irq_lock, flags);

	kfree(ic->irqs);
	kfree(ic);
}

void irq_enable(unsigned int irq)
{
	unsigned long flags = 0;
	struct irq_desc *d = NULL;

	spin_lock_irqsave(&__irq_lock, flags);

	d = __irq_to_desc(irq);
	if (d)
		__irq_enable(d->controller, d, false);

	spin_unlock_irqrestore(&__irq_lock, flags);
}

void irq_disable(unsigned int irq)
{
	unsigned long flags = 0;
	struct irq_desc *d = NULL;
	struct irq_controller *ic = NULL;

	spin_lock_irqsave(&__irq_lock, flags);

	d = __irq_to_desc(irq);
	if (d == NULL || (d->handler == NULL))
		goto out;

	ic = d->controller;
	if (ic->ops->irq_disable) {
		ic->ops->irq_disable(d);

		if (IRQ_IS_PERCPU(ic, d)) {
			cpu_affinity_clear(d->affinity, percpu_id());
			if (cpu_affinity_empty(d->affinity))
				irq_clear_enable(d);
		} else
			irq_clear_enable(d);
	}

	/* disable the parent if d is the only child of its parent */
	while (d->parent) {
		d = d->parent;
		ic = d->controller;
		if (!IRQ_IS_PERCPU(ic, d) &&
			(d->childcnt == 1)) {
			/* skip controller's irq */
			if (d->flags & IRQ_IS_CONTROLLER)
				break;
			if (ic->ops->irq_disable)
				ic->ops->irq_disable(d);
			irq_clear_enable(d);
		}
	}

out:
	spin_unlock_irqrestore(&__irq_lock, flags);
}

/*
 * Invoke the handler @ corrsponding interrupt desc.
 */
void irq_generic_handle(struct irq_desc *desc)
{
	if (desc == NULL)
		return;

	/* increase the irq count */
	desc->percpucnt[percpu_id()]++;

	if (desc->handler)
		desc->handler(desc->data);
}

void *irq_handler(struct thread_ctx *regs)
{
	struct percpu *pc = thiscpu;
	struct irq_controller *root_controller = NULL;

	pc->in_interrupt = true;
	pc->int_ctx = regs;

	root_controller = list_first_entry_or_null(
		&__controllers, struct irq_controller, node);

	root_handler(root_controller, regs);

	pc->int_ctx = NULL;
	pc->in_interrupt = false;

	return regs;
}

void irq_set_root_handler(irq_root_handler_t handler)
{
	root_handler = handler;
}

static int __irq_set_affinity(struct irq_controller *ic,
	struct irq_desc *d, const struct cpu_affinity *affinity)
{
	int ret = 0;
	struct irq_desc *dparent = NULL;
	struct irq_controller *parent = NULL;

	if (!ic->ops->irq_set_affinity)
		return -ENOSYS;

	/* set the parent affinity if d is the only child of its parent */
	dparent = d->parent;
	if (dparent && (dparent->childcnt == 1)) {
		parent = dparent->controller;
		ret = __irq_set_affinity(parent, dparent, affinity);
		if (parent->ops->irq_set_affinity && ret)
			return ret;
	}

	return ic->ops->irq_set_affinity(d, affinity, false);
}

int irq_set_affinity(unsigned int irq,
	const struct cpu_affinity *affinity)
{
	int ret = -EINVAL;
	unsigned long flags = 0;
	struct irq_desc *d = NULL;

	spin_lock_irqsave(&__irq_lock, flags);

	d = __irq_to_desc(irq);
	if (d && d->handler)
		ret = __irq_set_affinity(d->controller, d, affinity);

	spin_unlock_irqrestore(&__irq_lock, flags);

	return ret;
}

/*
 * For STR, suspend the IRQ-controllers and IRQs
 */
static int irq_suspend(void *data)
{
	struct irq_desc *d = NULL;
	struct irq_controller *ic = NULL;

	rb_for_each_entry_reverse(d, __irq_rbroot, rbnode) {
		if (d->controller->ops->irq_suspend)
			d->controller->ops->irq_suspend(d);
	}

	list_for_each_entry_reverse(ic, &__controllers, node) {
		if (ic->ops->irq_controller_suspend)
			ic->ops->irq_controller_suspend(ic);
	}

	return 0;
}

/*
 * For STR, resume the IRQ-controllers and IRQs
 */
static int irq_resume(void *data)
{
	struct irq_desc *d = NULL;
	struct irq_controller *ic = NULL;

	list_for_each_entry(ic, &__controllers, node) {
		if (ic->ops->irq_controller_resume)
			ic->ops->irq_controller_resume(ic);
	}

	rb_for_each_entry(d, __irq_rbroot, rbnode) {
		if (d->controller->ops->irq_resume)
			d->controller->ops->irq_resume(d);
	}

	return 0;
}
DECLARE_STR_ARCH(irq, irq_suspend, irq_resume, NULL);

/*
 * For CPU Hot-Plug
 * migrating the Shared-IRQs to a live CPU
 */
void irq_migrating(void)
{
	struct irq_desc *d = NULL;
	unsigned long flags = 0;
	const struct irq_controller *ic = NULL;
	struct percpu *pc = thiscpu;

	spin_lock_irqsave(&__irq_lock, flags);

	rb_for_each_entry(d, __irq_rbroot, rbnode) {
		ic = d->controller;

		if (!ic->ops->irq_set_affinity)
			continue;

		if (!irq_is_enabled(d))
			continue;

		if (IRQ_IS_PERCPU(ic, d))
			continue;

		cpu_affinity_clear(d->affinity, pc->id);

		IMSG("irq %d hwirq %d @ %s\n", d->irq, d->hwirq,
			ic->dn ? ic->dn->id.name : ic->ops->name);

		ic->ops->irq_set_affinity(d, d->affinity, false);

		/* resume - this cpu may be online again ? */
		cpu_affinity_set(d->affinity, pc->id);
	}

	pc->in_interrupt = false;

	spin_unlock_irqrestore(&__irq_lock, flags);
}

void __init irq_init(void)
{
	struct device_node *dn = NULL, *parent = NULL;
	struct device_node *from = NULL;
	struct of_compat_init *start = NULL;
	struct of_compat_init *end = NULL;
	struct of_compat_init *oci = NULL;
	struct of_irq_init_desc {
		struct of_compat_init *oci;
		struct device_node *dn;
		struct device_node *parent;
		struct list_head node;
	} *d = NULL, *_d = NULL, *p = NULL;
	unsigned long needworking = 0;

	LIST_HEAD(unfinished); LIST_HEAD(finished);

	start = __irq_init_start();
	end = __irq_init_end();

	for (oci = start; oci < end; oci++) {
		if (oci->init == NULL)
			continue;

		from = NULL;

		do {
			dn = of_find_compatible_node(from, oci->compat);
			if (dn == NULL)
				break;

			if (!of_property_read_bool(dn, "interrupt-controller"))
				break;

			d = kmalloc(sizeof(struct of_irq_init_desc));
			if (d == NULL)
				return;

			parent = of_irq_find_parent(dn);

			d->oci = oci;
			d->dn = dn;
			d->parent = parent;

			/* root controller, init it directly */
			if (parent == NULL) {
				oci->init(dn);
				list_add_tail(&d->node, &finished);
			} else {
				list_add_tail(&d->node, &unfinished);
			}

			from = dn;
		} while (1);
	}

	do {
		needworking = 0;
		list_for_each_entry_safe(d, _d, &unfinished, node) {
			list_for_each_entry(p, &finished, node) {
				if (d->parent == p->dn) {
					d->oci->init(d->dn);
					list_move_tail(&d->node, &finished);
					needworking++;
					break;
				}
			}
		}

		/* finished all, or children has no parents */
	} while (needworking);

	list_for_each_entry_safe(d, _d, &unfinished, node) {
		EMSG("%s has no parents\n", d->oci->compat);
		list_del(&d->node);
		kfree(d);
	}

	list_for_each_entry_safe(d, _d, &finished, node) {
		list_del(&d->node);
		kfree(d);
	}
}

static struct softint_desc {
	/* interrupt provider */
	struct irq_controller *controller;

	/* id of IPI/RPC Callee/Caller's source interrupt */
	unsigned int hwirqs[SOFTINT_MAX];

	bool shareirq;

	/* who is raising */
	struct atomic_num raising[CONFIG_NR_CPUS][SOFTINT_MAX];

	/* record the processed count */
	unsigned int percpucnt[CONFIG_NR_CPUS][SOFTINT_MAX];

	irq_softint_handler_t handlers[SOFTINT_MAX];

	void *datas[SOFTINT_MAX];
} softint_desc = {NULL};

/*
 * set the HW interrupt sources for the softint
 */
void softint_init(struct irq_controller *ic,
	unsigned int *hwirqs, unsigned int nrirqs)
{
	int i = 0;
	struct softint_desc *softint = &softint_desc;

	softint->controller = ic;

	memcpy(softint->hwirqs, hwirqs, nrirqs * sizeof(int));

	if (nrirqs == 1) {
		softint->shareirq = true;

		for (i = 1; i < SOFTINT_MAX; i++)
			softint->hwirqs[i] = *hwirqs;
	}
}

static void softint_common_handler(void *data)
{
	void *handlerdata = NULL;
	irq_softint_handler_t handler;
	int cpu = percpu_id(), val = 0, cnt = 0;
	struct softint_desc *softint = data;
	struct atomic_num *atn = &softint->raising[cpu][SOFTINT_IPI];

more:
	if ((val = atomic_read(atn)) != 0) {
		handler = softint->handlers[SOFTINT_IPI];
		handlerdata = softint->datas[SOFTINT_IPI];
		if (handler) {
			cnt = handler(handlerdata);
			softint->percpucnt[cpu][SOFTINT_IPI] += cnt;
		}
	}

	if (softint->shareirq) {
		handler = softint->handlers[SOFTINT_RPC_CALLEE];
		handlerdata = softint->datas[SOFTINT_RPC_CALLEE];
		if (handler) {
			cnt = handler(handlerdata);
			softint->percpucnt[cpu][SOFTINT_RPC_CALLEE] += cnt;
		}
	}

	if (!atomic_compare_set(atn, &val, 0))
		goto more;
}

static void softint_rpc_handler(void *data)
{
	int cpu = percpu_id(), cnt = 0;
	void *handlerdata = NULL;
	irq_softint_handler_t handler;
	struct softint_desc *softint = data;

	handler = softint->handlers[SOFTINT_RPC_CALLEE];
	handlerdata = softint->datas[SOFTINT_RPC_CALLEE];
	cnt += handler(handlerdata);
	softint->percpucnt[cpu][SOFTINT_RPC_CALLEE] += cnt;
}

/*
 * Register the softint @ id
 * return 0 on success
 */
int softint_register(unsigned int id,
	irq_softint_handler_t handler, void *data)
{
	unsigned int hwirq = 0;
	unsigned long flags = 0, ret = 0;
	struct irq_desc *d = NULL;
	struct irq_controller *ic = NULL;
	struct softint_desc *softint = &softint_desc;
	irq_handler_t handlerwrap = softint_common_handler;

	if (id >= SOFTINT_MAX)
		return -EINVAL;

	spin_lock_irqsave(&__irq_lock, flags);

	ic = softint->controller;
	if (ic == NULL)
		goto out;

	hwirq = softint->hwirqs[id];
	softint->handlers[id] = handler;
	softint->datas[id] = data;

	if (id == SOFTINT_RPC_CALLEE) {
		/* RPC has dedicated hwirq ? */
		if (!softint->shareirq)
			handlerwrap = softint_rpc_handler;
		else if (irq_to_desc_hw(ic, hwirq))
			goto out; /* already registered */
	}

	if (id == SOFTINT_RPC_CALLER)
		handlerwrap = NULL;

	d = irq_to_desc_hw(ic, hwirq);
	if (d == NULL) {
		IMSG("%d -> %s\n", hwirq, ic->ops->name);
		d = __irq_alloc(ic, hwirq, 0, handlerwrap, softint);
		if (d == NULL) {
			ret = -ENOMEM;
			goto out;
		}
	}

	if (ic->ops->irq_enable && (id != SOFTINT_RPC_CALLER)) {
		ic->ops->irq_enable(d);
		irq_set_enable(d);
	}

out:
	spin_unlock_irqrestore(&__irq_lock, flags);
	return ret;
}

/*
 * Unegister the softint
 */
void softint_unregister(unsigned int id)
{
	unsigned long flags = 0;
	unsigned int hwirq = 0;
	struct irq_desc *d = NULL;
	struct irq_controller *ic = NULL;
	struct softint_desc *softint = &softint_desc;

	if (id >= SOFTINT_MAX)
		return;

	if (softint->controller == NULL)
		return;

	spin_lock_irqsave(&__irq_lock, flags);

	hwirq = softint->hwirqs[id];

	softint->handlers[id] = NULL;
	softint->datas[id] = NULL;

	ic = softint->controller;

	d = irq_to_desc_hw(ic, hwirq);
	if (d) {
		if (!softint->shareirq)
			__irq_free(d);
	}

	spin_unlock_irqrestore(&__irq_lock, flags);
}

/*
 * Raise a softint on the
 * processor specified by @cpu (except RPC_CALLER)
 */
void softint_raise(unsigned int id, unsigned int cpu)
{
	unsigned int hwirq = 0;
	unsigned long flags = 0;
	struct irq_desc *d = NULL;
	struct irq_controller *ic = NULL;
	struct softint_desc *softint = &softint_desc;

	if (!VALID_CPUID(cpu) || (id >= SOFTINT_MAX))
		return;

	if (softint->controller == NULL)
		return;

	spin_lock_irqsave(&__irq_lock, flags);

	ic = softint->controller;
	hwirq = softint->hwirqs[id];
	d = irq_to_desc_hw(ic, hwirq);

	if (d != NULL) {
		if (id == SOFTINT_RPC_CALLER) {
			/* counting the RPC caller */
			softint->percpucnt[cpu][id] += 1;

			/*
			 * RPC calls to Peer Execution Environment - todo
			 */
			if (IS_ENABLED(CONFIG_RISCV) && IS_ENABLED(CONFIG_RPC)) {
				extern int rpc_calleeid(void);
				cpu = rpc_calleeid();
			}
		} else
			 atomic_inc(&softint->raising[cpu][id]);

		ic->ops->irq_send(d, cpu);
	} else
		WMSG("%d @ %s is unregistered ?\n", hwirq, ic->ops->name);

	spin_unlock_irqrestore(&__irq_lock, flags);
}


#if defined(CONFIG_DEBUGFS)

static void irq_print_nr(struct debugfs_file *d,
	unsigned long val, int nrchars)
{
	size_t len = 0;
	char tmp[32] = {0};

	len = snprintf(tmp, sizeof(tmp), "%ld", val);
	if (len < nrchars) {
		memset(tmp + len, ' ', nrchars - len);
		debugfs_printf(d, "%s", tmp);
	}
}

static int irq_debugfs_read(struct debugfs_file *d)
{
	int cpu = 0, i = 0;
	unsigned long flags = 0, total = 0;
	struct irq_desc *irqd = NULL;
	struct irq_controller *ic = NULL;

	debugfs_printf(d, "irq\thwirq\tparent\tchilds\tenabled\taffinity");
	debugfs_printf(d, "  total-cnt   percpu-cnt         controller\n");

	spin_lock_irqsave(&__irq_lock, flags);

	rb_for_each_entry(irqd, __irq_rbroot, rbnode) {
		ic = irqd->controller;

		/* irq and hwirq */
		debugfs_printf(d, "%d\t%d", irqd->irq, irqd->hwirq);
		/* check the handler */
		if (!irqd->handler)
			debugfs_printf(d, "(nil)");

		/* parent-irq */
		if (irqd->parent)
			debugfs_printf(d, "\t%d\t", irqd->parent->irq);
		else
			debugfs_printf(d, "\troot\t");

		/* number of childs */
		debugfs_printf(d, "%d\t", irqd->childcnt);
		/* is enabled ? */
		debugfs_printf(d, "%d\t", irq_is_enabled(irqd));

		/* affinity, only show a LONG type bits */
		debugfs_printf(d, "%lx\t  ", ioreadl(irqd->affinity));

		/* total counts */
		total = 0;
		for (i = 0; i < CONFIG_NR_CPUS; i++)
			total += irqd->percpucnt[i];
		irq_print_nr(d, total, 12);

		/* percpu counts */
		for_each_online_cpu(cpu) {
			if (cpu == 0) {
				debugfs_printf(d, "CPU%02d: ", cpu);
				irq_print_nr(d, irqd->percpucnt[cpu], 12);
				debugfs_printf(d, "%s\n", ic->ops->name);
			} else {
				debugfs_printf(d, "\t\t\t\t\t\t\t      CPU%02d: ", cpu);
				irq_print_nr(d, irqd->percpucnt[cpu], 12);
				debugfs_printf(d, "\n");
			}
		}
		debugfs_printf(d, "\n");
	}

	struct softint_desc *softint = &softint_desc;

	const char *softint_names[SOFTINT_MAX] = {
		"RPC_CALLER: ", "RPC_CALLEE: ", "IPI:   "
	};

	for (i = SOFTINT_MAX - 1; i >= 0; i--) {
		debugfs_printf(d, "%s", softint_names[i]);

		total = 0;
		for (cpu = 0; cpu < CONFIG_NR_CPUS; cpu++)
			total += softint->percpucnt[cpu][i];
		irq_print_nr(d, total, 12);
	}
	debugfs_printf(d, "\n");

	for_each_online_cpu(cpu) {
		for (i = SOFTINT_MAX - 1; i >= 0; i--) {
			if (i == 2)
				debugfs_printf(d, "CPU%02d: ", cpu);
			else
				debugfs_printf(d, "CPU%02d:      ", cpu);
			irq_print_nr(d, softint->percpucnt[cpu][i], 12);
		}
		debugfs_printf(d, "\n");
	}

	spin_unlock_irqrestore(&__irq_lock, flags);

	return 0;
}

static const struct debugfs_fops irq_info_debugfs_ops = {
	.read = irq_debugfs_read,
	.write = NULL,
};

static void __init irq_debugfs_init(void)
{
	debugfs_create("/irq", &irq_info_debugfs_ops);
}

MODULE_INIT(irq_debugfs_init);

#endif
