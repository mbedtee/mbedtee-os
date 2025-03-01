// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Kernel-level Call Stack Backtrace (kthread only, unwind method)
 */

#include <init.h>
#include <sections.h>
#include <trace.h>
#include <string.h>
#include <thread.h>
#include <unwind.h>
#include <backtrace.h>

#if defined(CONFIG_UART)
#define BACKTRACE_SERIAL_ONLY
extern void uart_early_puts(const char *str, size_t cnt);
#endif

const char *ksymname_of(unsigned long addr, unsigned long *offset)
{
	unsigned int low = 0;
	unsigned int mid = 0;
	unsigned int high = ksymnum;

	while (high > low + 1) {
		mid = low + (high - low) / 2;
		if (ksymaddr[mid] <= addr)
			low = mid;
		else
			high = mid;
	}

	if (((low == 0) && (ksymaddr[low] > addr)) ||
		((high == ksymnum) && (ksymaddr[low] < addr)))
		return NULL;

	if (offset)
		*offset = addr - ksymaddr[low];

	return &ksymname[ksymoffset[low]];
}

static _Unwind_Reason_Code __tracer(struct _Unwind_Context *ctx, void *d)
{
	int *depth = (int *)d;
	unsigned long offset = -1;
	unsigned long lreg = _Unwind_GetIP(ctx);
	const char *name = NULL;
	char tracestr[128];
	static unsigned long lastlreg;

	name = ksymname_of(lreg, &offset);
	if (name == NULL)
		return _URC_NO_REASON;

	/* skip the backtrace() itself */
	if (strstr(name, "backtrace"))
		return _URC_NO_REASON;

	if (sizeof(long) == sizeof(int))
		snprintf(tracestr, sizeof(tracestr),
			"#%d        <%lx>                        (%s + 0x%lx)\n",
			*depth, lreg, name ? name : "null", offset);
	else
		snprintf(tracestr, sizeof(tracestr),
			"#%d        <%lx>                (%s + 0x%lx)\n",
			*depth, lreg, name ? name : "null", offset);

#if defined(BACKTRACE_SERIAL_ONLY)
	uart_early_puts(tracestr, strlen(tracestr));
#else
	printk_raw(tracestr, strlen(tracestr));
#endif

	if (lastlreg == lreg)
		return _URC_END_OF_STACK;

	lastlreg = lreg;
	*depth += 1;

	return _URC_NO_REASON;
}

void backtrace(void)
{
	int depth = 0;
	char *name = current->name;

	local_irq_disable();

#if defined(BACKTRACE_SERIAL_ONLY)
	uart_early_puts(name, strnlen(name, THREAD_NAME_LEN));
	uart_early_puts(" kbacktrace\n", 12);
	_Unwind_Backtrace(&__tracer, &depth);
#else
	printk_raw(name, strnlen(name, THREAD_NAME_LEN));
	printk_raw(" kbacktrace\n", 12);
	_Unwind_Backtrace(&__tracer, &depth);
#endif
}

/* only AArch32 is using exidx, others using ehframe */
#if !defined(__arm__)
static void __init unwind_frame_init(void)
{
	__register_frame(__EHFRAME_START);
}
EARLY_INIT(unwind_frame_init);
#endif
