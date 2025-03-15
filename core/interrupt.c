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

/* IRQ enable or disable flags */
#define IRQ_ENABLED  (1 << 0)
#define IRQ_DISABLED (1 << 1)

/* support multi-interrupt-controllers */
static LIST_HEAD(__controllers);
static SPIN_LOCK(__controllers_lock);

static struct irq_controller *__softint_controller;

/* lock for IRQ-IDA and Red-Black-Tree */
static SPIN_LOCK(__irq_lock);
static DECLARE_BITMAP(__irqida, IRQ_MAX);
static unsigned int __irq_idnext = 1;
static struct rb_node *__irq_rbroot;

static void (*root_handler)(struct thread_ctx *);

#define IRQ_IS_PERCPU(ctrl, desc) (((ctrl)->flags & IRQCTRL_PERCPU) || \
	((ctrl)->ops->irq_is_percpu && (ctrl)->ops->irq_is_percpu(desc)))

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

struct irq_controller *__irq_create_controller(struct device_node *dn,
	unsigned int nr_irqs, const struct irq_controller_ops *ops, unsigned int iflag)
{
	struct irq_controller *ic = NULL;
	unsigned long flags = 0, structsz = 0;

	if (nr_irqs > IRQ_MAX)
		return NULL;

	structsz = sizeof(struct irq_controller);

	structsz += (nr_irqs * sizeof(struct irq_desc *));

	ic = kzalloc(structsz);
	if (ic == NULL)
		return NULL;

	ic->dn = dn;
	ic->ops = ops;
	ic->flags = iflag;
	ic->start = 0;
	ic->nr_irqs = nr_irqs;
	ic->parent = irq_parent_controller(dn);

	spin_lock_irqsave(&__controllers_lock, flags);
	if (iflag & IRQCTRL_SOFTINT)
		__softint_controller = ic;
	else
		list_add_tail(&ic->node, &__controllers);
	spin_unlock_irqrestore(&__controllers_lock, flags);

	return ic;
}

void irq_remove_controller(struct irq_controller *ic)
{
	unsigned long flags = 0, i = 0;
	struct irq_desc *d = NULL;

	spin_lock_irqsave(&__controllers_lock, flags);
	if (flags & IRQCTRL_SOFTINT)
		__softint_controller = NULL;
	else
		list_del(&ic->node);
	spin_unlock_irqrestore(&__controllers_lock, flags);

	for (i = 0; i < ic->nr_irqs; i++) {
		d = ic->irqs[i];
		if (d != NULL) {
			WMSG("irq %d hwirq %d @ %s still inuse\n",
				d->irq, d->hwirq, ic->dn ?
				ic->dn->id.name : ic->ops->name);
		}
	}

	kfree(ic);
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
	return rb_entry_of(n, struct irq_desc, rbnode)->irq -
			rb_entry_of(ref, struct irq_desc, rbnode)->irq;
}

static int __irq_free(struct irq_desc *d)
{
	struct irq_controller *ic = d->controller;
	const char *name = ic->dn ? ic->dn->id.name : ic->ops->name;

	if (d->childcnt) {
		WMSG("hwirq %d @ %s - %d child inuse\n", d->hwirq,
			name, d->childcnt);
		return -EBUSY;
	}

	if (IRQ_IS_PERCPU(ic, d)) {
		cpu_affinity_clear(d->affinity, percpu_id());
		if (!cpu_affinity_empty(d->affinity)) {
			WMSG("hwirq %d @ %s - cpumap(%lx) inuse\n", d->hwirq,
				name, ioreadl(d->affinity));
			return -EBUSY;
		}
	}

	IMSG("irq %d hwirq %d @ %s\n", d->irq, d->hwirq, name);

	if (ic->ops->irq_disable && !d->disabled)
		ic->ops->irq_disable(d);

	/* del the irq desc from OS global rb-tree */
	rb_del(&d->rbnode, &__irq_rbroot);

	/* unlink the irq desc with hwirq @ controller */
	ic->irqs[d->hwirq - ic->start] = NULL;

	bitmap_clear_bit(__irqida, d->irq);

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

	/* parent exist ? */
	while (dparent) {
		dparent->childcnt--;
		__irq_free(dparent);
		dparent = dparent->parent;
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

	__irq_idnext = irq + 1;
	bitmap_set_bit(__irqida, irq);

	if (irq == IRQ_MAX) {
		kfree(desc);
		return NULL;
	}

	desc->irq = irq;
	return desc;
}

static struct irq_desc *__irq_alloc(struct irq_controller *ic,
	unsigned int hwirq, irq_handler_t handler, void *data)
{
	struct irq_desc *d = NULL;

	IMSG("%d @ %s\n", hwirq, ic->dn ? ic->dn->id.name : ic->ops->name);

	/* already registered */
	d = irq_to_desc_hw(ic, hwirq);
	if (d != NULL) {
		if (IRQ_IS_PERCPU(ic, d))
			cpu_affinity_set(d->affinity, percpu_id());
		if (ic->ops->irq_enable && handler)
			ic->ops->irq_enable(d);
		return d;
	}

	d = __irq_alloc_desc();
	if (d == NULL)
		return NULL;

	d->hwirq = hwirq;
	d->controller = ic;
	d->handler = handler;
	d->data = data;

	if (IRQ_IS_PERCPU(ic, d))
		cpu_affinity_set(d->affinity, percpu_id());
	else if (ic->ops->irq_set_affinity)
		cpu_affinity_fill(d->affinity);

	/* link the irq desc with hwirq @ controller */
	ic->irqs[hwirq - ic->start] = d;
	/* add the irq desc to OS global rb-tree */
	rb_add(&d->rbnode, &__irq_rbroot, __irq_rbadd_cmp);

	if (ic->ops->irq_enable && handler)
		ic->ops->irq_enable(d);

	return d;
}

static int __irq_register(struct irq_controller *ic,
	unsigned int hwirq, irq_handler_t handler, void *data)
{
	int ret = 0, depth = 0;
	struct irq_desc *d = NULL;
	struct irq_desc *dchild = NULL;
	struct irq_desc *dparent = NULL;
	struct irq_controller *curr = ic;
	struct irq_controller *parent = NULL;
	unsigned int parentirq = 0;
	irq_handler_t phandler = NULL;

	if (hwirq >= ic->nr_irqs + ic->start)
		return -EINVAL;

	d = __irq_alloc(ic, hwirq, handler, data);
	if (d == NULL)
		return -ENOMEM;

	curr = ic;
	dchild = d;
	while (curr->ops->irq_parent) {
		parent = curr->parent;
		if (parent == NULL)
			break;

		phandler = NULL;
		ret = curr->ops->irq_parent(dchild, &parentirq, &phandler);
		if (ret != 0)
			goto out;

		if (parentirq >= parent->nr_irqs + parent->start) {
			ret = -EINVAL;
			goto out;
		}

		phandler = phandler ? phandler : handler;
		dparent = __irq_alloc(parent, parentirq, phandler, data);
		if (dparent == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		depth++;
		curr = parent;
		dparent->childcnt++;
		dchild->parent = dparent;
		dchild = dchild->parent;
	}

out:
	if (ret != 0) {
		dparent = d->parent;
		__irq_free(d);

		/* free the parents we just allocated */
		while (dparent && depth) {
			depth--;
			dparent->childcnt--;
			__irq_free(dparent);
			dparent = dparent->parent;
		}

		return ret;
	}
	return d->irq;
}

int irq_register(struct irq_controller *ic,
	unsigned int hwirq, irq_handler_t handler, void *data)
{
	int ret = -1;
	unsigned long flags = 0;

	if (ic == NULL)
		ic = list_first_entry_or_null(&__controllers,
			struct irq_controller, node);

	if (ic == NULL)
		return -EINVAL;

	spin_lock_irqsave(&__irq_lock, flags);

	ret = __irq_register(ic, hwirq, handler, data);

	spin_unlock_irqrestore(&__irq_lock, flags);

	return ret;
}

void irq_enable(unsigned int irq)
{
	unsigned long flags = 0;
	struct irq_desc *d = NULL;
	struct irq_controller *ic = NULL;

	spin_lock_irqsave(&__irq_lock, flags);

	d = __irq_to_desc(irq);
	if (d == NULL)
		goto out;

	ic = d->controller;

	if (ic->ops->irq_enable && d->handler)
		ic->ops->irq_enable(d);

	if (IRQ_IS_PERCPU(ic, d))
		cpu_affinity_set(d->affinity, percpu_id());
	else
		d->disabled = false;

out:
	spin_unlock_irqrestore(&__irq_lock, flags);
}

void irq_disable(unsigned int irq)
{
	unsigned long flags = 0;
	struct irq_desc *d = NULL;
	struct irq_controller *ic = NULL;

	spin_lock_irqsave(&__irq_lock, flags);

	d = __irq_to_desc(irq);
	if (d == NULL)
		goto out;

	ic = d->controller;

	if (ic->ops->irq_disable)
		ic->ops->irq_disable(d);

	if (IRQ_IS_PERCPU(ic, d))
		cpu_affinity_clear(d->affinity, percpu_id());
	else
		d->disabled = true;

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

	pc->in_interrupt = true;
	pc->int_ctx = regs;

	assert(root_handler);

	root_handler(regs);

	pc->int_ctx = NULL;
	pc->in_interrupt = false;

	return regs;
}

void irq_set_root_handler(void (*root)(struct thread_ctx *))
{
	root_handler = root;
}

int irq_set_affinity(unsigned int irq,
	const struct cpu_affinity *affinity)
{
	int ret = -EINVAL;
	unsigned long flags = 0;
	struct irq_desc *d = irq_to_desc(irq);
	const struct irq_controller *ic = NULL;

	if (d == NULL)
		return ret;

	spin_lock_irqsave(&__irq_lock, flags);

	ic = d->controller;

	if (!IRQ_IS_PERCPU(ic, d) && ic->ops->irq_set_affinity)
		ret = ic->ops->irq_set_affinity(d, affinity);

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

	ic = __softint_controller;
	if (ic->ops->irq_controller_suspend)
		ic->ops->irq_controller_suspend(ic);

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

	ic = __softint_controller;
	if (ic->ops->irq_controller_resume)
		ic->ops->irq_controller_resume(ic);

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

		if (d->disabled)
			continue;

		if (IRQ_IS_PERCPU(ic, d))
			continue;

		cpu_affinity_clear(d->affinity, pc->id);

		IMSG("irq %d hwirq %d @ %s\n", d->irq, d->hwirq,
			ic->dn ? ic->dn->id.name : ic->ops->name);

		ic->ops->irq_set_affinity(d, d->affinity);

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

/*
 * Register the softint @ id
 */
int register_softint(unsigned int id,
	irq_handler_t handler, void *data)
{
	unsigned long flags = 0, ret = -ENOTSUP;
	struct irq_controller *ic = NULL;

	if (id >= SOFTINT_MAX)
		return -EINVAL;

	spin_lock_irqsave(&__controllers_lock, flags);

	ic = __softint_controller;

	if (ic)
		ret = irq_register(ic, id, handler, data);

	spin_unlock_irqrestore(&__controllers_lock, flags);

	return ret;
}

/*
 * Unegister the softint
 */
void unregister_softint(unsigned int id)
{
	unsigned long flags = 0;
	struct irq_controller *ic = NULL;
	struct irq_desc *d = NULL;

	if (id >= SOFTINT_MAX)
		return;

	spin_lock_irqsave(&__controllers_lock, flags);

	ic = __softint_controller;

	if (ic) {
		d = irq_to_desc_hw(ic, id);

		if (d != NULL)
			irq_unregister(d->irq);
		else
			WMSG("%d @ %s is unregistered ?\n", id, ic->ops->name);
	}

	spin_unlock_irqrestore(&__controllers_lock, flags);
}

/*
 * Raise a softint on the
 * processor specified by @cpu_id
 */
void raise_softint(unsigned int id, unsigned int cpu_id)
{
	unsigned long flags = 0;
	struct irq_controller *ic = NULL;
	struct irq_desc *d = NULL;

	if (!VALID_CPUID(cpu_id) || (id >= SOFTINT_MAX))
		return;

	spin_lock_irqsave(&__controllers_lock, flags);

	ic = __softint_controller;

	if (ic) {
		d = irq_to_desc_hw(ic, id);

		if (d != NULL)
			ic->ops->irq_send(d, cpu_id);
		else
			WMSG("%d @ %s is unregistered ?\n", id, ic->ops->name);
	}

	spin_unlock_irqrestore(&__controllers_lock, flags);
}

#if defined(CONFIG_DEBUGFS)

static void irq_debugfs_print_nr(struct debugfs_file *d,
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
	unsigned int cpu = 0, i = 0;
	unsigned long flags = 0, total = 0;
	struct irq_desc *irqd = NULL;
	struct irq_controller *ic = NULL;

	debugfs_printf(d, "irq\thwirq\tparent\taffinity  total-cnt   percpu-cnt       controller\n");

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
			debugfs_printf(d, "\tnil\t");

		/* affinity, only show a LONG type bits */
		debugfs_printf(d, "%lx\t  ", *(long *)irqd->affinity);

		/* total counts */
		total = 0;
		for (i = 0; i < CONFIG_NR_CPUS; i++)
			total += irqd->percpucnt[i];
		irq_debugfs_print_nr(d, total, 12);

		/* percpu counts */
		for_each_online_cpu(cpu) {
			if (cpu == 0) {
				debugfs_printf(d, "CPU%d: ", cpu);
				irq_debugfs_print_nr(d, irqd->percpucnt[cpu], 11);
				debugfs_printf(d, "%s\n", ic->ops->name);
			} else {
				debugfs_printf(d, "\t\t\t\t\t      CPU%d: ", cpu);
				irq_debugfs_print_nr(d, irqd->percpucnt[cpu], 11);
				debugfs_printf(d, "\n");
			}
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
