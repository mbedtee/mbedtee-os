// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * UART Module Core
 */

#include <io.h>
#include <of.h>
#include <str.h>
#include <kmap.h>
#include <list.h>
#include <uart.h>
#include <sched.h>
#include <trace.h>
#include <thread.h>
#include <driver.h>
#include <device.h>
#include <kmalloc.h>
#include <interrupt.h>
#include <sys/poll.h>
#include <sys/mmap.h>

#define UART_MAX_PORT 10

static LIST_HEAD(uart_ports);
static struct of_device_id of_uart_port_ids[UART_MAX_PORT] = {{NULL}};

#define for_each_uart_port(p) list_for_each_entry(p, &uart_ports, node)

void uart_early_puts(const char *str, size_t cnt)
{
	struct uart_port *p = list_first_entry_or_null(
			&uart_ports, struct uart_port, node);

	if (p)
		p->ops->tx(p, str, cnt);
}

int uart_register(struct uart_port *p)
{
	int i = 0;

	/*
	 * of course there is no race condition
	 */
	struct uart_port *ep = NULL;

	for_each_uart_port(ep) {
		if (ep->iobase == p->iobase)
			return -EEXIST;
	}
	list_add_tail(&p->node, &uart_ports);

	for (i = 0; i < UART_MAX_PORT; i++) {
		if (of_uart_port_ids[i].name != NULL &&
			of_name_equal(p->dn, of_uart_port_ids[i].name) &&
			of_compatible_equal(p->dn, of_uart_port_ids[i].compat))
			return 0;
	}

	for (i = 0; i < UART_MAX_PORT; i++) {
		if (of_uart_port_ids[i].name == NULL) {
			p->idx = i;
			memcpy(&of_uart_port_ids[i], &p->dn->id, sizeof(p->dn->id));
			break;
		}
	}

	return 0;
}

void uart_unregister(struct uart_port *p)
{
	list_del(&p->node);
}

static struct uart_port *of_uart_port(
	const struct device *dev)
{
	struct uart_port *p = NULL;

	for_each_uart_port(p) {
		if (&p->dn->dev == dev)
			return p;
	}

	return NULL;
}

static int uart_open(struct file *f, mode_t mode, void *arg)
{
	struct uart_port *p = dev_get_drvdata(f->dev);

	if (p == NULL)
		return -ENODEV;

	f->priv = p;

	return 0;
}

static int uart_close(struct file *f)
{
	if (f->priv == NULL)
		return -ENODEV;

	return 0;
}

static ssize_t uart_read(struct file *f,
	void *buf, size_t count)
{
	ssize_t pos = 0;
	struct uart_port *p = f->priv;

	if (p == NULL)
		return -ENODEV;

	if (buf == NULL)
		return -EINVAL;

	if (p->ops->rx == NULL)
		return -ENXIO;

	if (count == 0)
		return 0;

	wait_event_interruptible(&p->wait_queue,
			((pos = p->ops->rx(p, buf, count)) != 0) ||
			(f->flags & O_NONBLOCK));

	return pos;
}

static ssize_t uart_write(struct file *f,
	const void *buf, size_t count)
{
	struct uart_port *p = f->priv;

	if (p == NULL)
		return -ENODEV;

	if (buf == NULL)
		return -EINVAL;

	if (p->ops->tx == NULL)
		return -ENXIO;

	if (count == 0)
		return 0;

	p->ops->tx(p, buf, count);

	return count;
}

static int uart_poll(struct file *f, struct poll_table *wait)
{
	int events = POLLOUT | POLLWRNORM;
	struct uart_port *p = f->priv;

	if (p == NULL)
		return -ENODEV;

	poll_wait(f, &p->wait_queue, wait);

	if (p->rd != p->wr)
		return events | POLLIN | POLLRDNORM;

	return events;
}

static int uart_suspend(struct device *dev)
{
	struct uart_port *p = dev_get_drvdata(dev);

	if (p && p->ops) {
		p->ops->suspend(p);
		return 0;
	}

	return -ENODEV;
}

static int uart_resume(struct device *dev)
{
	struct uart_port *p = dev_get_drvdata(dev);

	if (p && p->ops) {
		p->ops->resume(p);
		return 0;
	}

	return -ENODEV;
}

static const struct file_operations uart_fops = {
	.open = uart_open,
	.close = uart_close,
	.read = uart_read,
	.write = uart_write,
	.poll = uart_poll
};

static const struct str_operations uart_str = {
	.suspend = uart_suspend,
	.resume = uart_resume,
};

static void uart_remove(struct device *dev)
{
	struct uart_port *p = dev_get_drvdata(dev);

	p->ops->detach(p);
}

static int __init uart_probe(struct device *dev)
{
	struct uart_port *p = of_uart_port(dev);

	if (p == NULL)
		return -ENODEV;

	p->ops->attach(p);

	dev->fops = &uart_fops;
	dev->sops = &uart_str;

	dev_set_drvdata(dev, p);
	return 0;
}

static int __init uart_parse_dts(struct uart_port *p,
	struct device_node *dn)
{
	int ret = -1;
	unsigned int tmp = 0;

	p->dn = dn;

	ret = of_read_property_addr_size(dn, "reg", 0, &p->iobase, &p->iosize);
	if (ret)
		return ret;

	ret = of_property_read_u32(dn, "reg-io-width", &tmp);
	p->regiowidth = ret ? 1 : tmp;

	ret = of_property_read_u32(dn, "reg-shift", &tmp);
	p->regshift = ret ? 0 : tmp;

	p->membase = iomap(p->iobase, p->iosize);

	ret = of_property_read_u32(dn, "interrupts", &p->hwirq);
	if (ret)
		p->hwirq = -1;

	ret = of_property_read_u32(dn, "clock-frequency", &p->clk);
	if (ret)
		return ret;

	ret = of_property_read_u32(dn, "current-speed", &p->baudrate);
	if (ret)
		return ret;

	ret = of_property_read_u32(dn, "clock-divisor", &p->divisor);
	if (ret)
		return ret;

	return 0;
}

void __init uart_early_init(void)
{
	int ret = -1;
	struct uart_port *p = NULL;
	struct device_node *uartdn = NULL;
	struct device_node *child = NULL;
	struct of_compat_init *start = NULL;
	struct of_compat_init *end = NULL;
	struct of_compat_init *oci = NULL;

	start = __uart_init_start();
	end = __uart_init_end();

	uartdn = of_find_compatible_node(NULL, "module,uart");
	if (uartdn == NULL)
		return;

	for (oci = start; oci < end; oci++) {
		for_each_compatible_child_of_node(uartdn, child, oci->compat) {
			p = kzalloc(sizeof(struct uart_port));
			if (p == NULL)
				continue;

			ret = uart_parse_dts(p, child);
			if (ret != 0)
				continue;

			spin_lock_init(&p->lock);
			waitqueue_init(&p->wait_queue);
			dev_set_drvdata(&child->dev, p);

			ret = oci->init(child);
			if (ret != 0) {
				EMSG("failed to initialize %s - %d\n", oci->compat, ret);
				kfree(p);
				continue;
			}

			if (uart_register(p))
				kfree(p);
			else
				IMSG("%s\n", child->id.name);
		}
	}
}

static const struct device_driver of_uart_drv = {
	.name = "uart",
	.probe = uart_probe,
	.remove = uart_remove,
	.of_match_table = of_uart_port_ids,
};

module_root(of_uart_drv);
