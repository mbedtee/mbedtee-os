// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Kernel printf
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <spinlock.h>
#include <sched.h>
#include <trace.h>
#include <file.h>
#include <thread.h>
#include <printk.h>

#ifdef CONFIG_UART
#include <uart.h>
#endif

static char pbuf[CONFIG_NR_CPUS][512];
static SPIN_LOCK(printk_lock);
static struct file *outf;

void printk_setfd(struct file_desc *d)
{
	struct file *newf = NULL;
	struct file *oldf = NULL;
	unsigned long flags = 0;

	newf = d->file;
	file_get(newf);

	spin_lock_irqsave(&printk_lock, flags);
	oldf = outf;
	outf = newf;
	spin_unlock_irqrestore(&printk_lock, flags);

	file_put(oldf);
}

void printk_raw(const char *str, size_t size)
{
	struct file *f = NULL;
	unsigned long flags = 0;
	struct thread *t = current;

	spin_lock_irqsave(&printk_lock, flags);
	if (((f = outf) != NULL) && t)
		file_get(f);
	spin_unlock_irqrestore(&printk_lock, flags);

	/*
	 * if we have real thread/proc context
	 * and the printk has been redirected
	 */
	if (f && t) {
		f->fops->write(f, str, size);
		file_put(f);
	} else {
		if (IS_ENABLED(CONFIG_UART))
			uart_early_puts(str, size);
	}
}

void printk(const char *fmt, ...)
{
	va_list ap;
	size_t l = 0;
	int cpu = 0;
	unsigned long flags = 0;

	local_irq_save(flags);

	cpu = sched_getcpu();

	va_start(ap, fmt);
	l = vsnprintf(pbuf[cpu], sizeof(pbuf[cpu]), fmt, ap);
	va_end(ap);

	if (l < sizeof(pbuf[cpu]))
		printk_raw(pbuf[cpu], l);

	local_irq_restore(flags);
}
