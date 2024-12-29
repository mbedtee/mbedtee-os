// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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

static char pbuf[512] = {0};
static struct file_desc *outfdesc;

void printk_setfd(struct file_desc *d)
{
	outfdesc = d;
}

void printk_raw(const char *str, size_t size)
{
	struct file_desc *d = outfdesc;

	/*
	 * if we have real thread/proc context
	 * and the printk has been redirected
	 */
	if (d && current_id)
		d->file->fops->write(d->file, str, size);
	else {
#if defined(CONFIG_UART)
		uart_early_puts(str, size);
#endif
	}
}

void printk(const char *fmt, ...)
{
	va_list ap;
	size_t l = 0;
	unsigned long flags = 0;

	local_irq_save(flags);

	va_start(ap, fmt);
	l = vsnprintf(pbuf, sizeof(pbuf), fmt, ap);
	va_end(ap);

	if (l < sizeof(pbuf))
		printk_raw(pbuf, l);

	local_irq_restore(flags);
}
