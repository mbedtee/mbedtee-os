// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV Timer
 */

#include <of.h>
#include <io.h>
#include <str.h>
#include <timer.h>
#include <kmap.h>
#include <trace.h>
#include <tevent.h>
#include <interrupt.h>

static struct arch_timer riscv_timer = {0};

/* if Sstc does not present, forward the requests to M-Mode Timer */
#define MTIMER_BASE ((uintptr_t)riscv_timer.base)

/* __noinline is required to avoid optimization to ecall_xx */
static __noinline uint64_t riscv_read_cycles(void)
{
	if (sstc_supported()) {
#if defined(CONFIG_64BIT)
		return read_csr(CSR_TIME);
#else
		uint32_t v1 = 0, v0 = 0;

		do {
			v1 = read_csr(CSR_TIMEH);
			v0 = read_csr(CSR_TIME);
		} while (v1 != read_csr(CSR_TIMEH));

		return ((uint64_t)v1 << 32) | v0;
#endif
	} else {
		return (uint64_t)ecall(ECALL_RDTIME, 0,	0, MTIMER_BASE);
	}
}

static void riscv_trigger_next(uint64_t cycles)
{
	uint64_t val = riscv_read_cycles() + cycles;

	set_csr(CSR_IE, IE_TIE);

	if (sstc_supported()) {
#if defined(CONFIG_64BIT)
		write_csr(CSR_STIMECMP, val);
#else
		uint32_t hi = val >> 32;
		uint32_t lo = val;

		write_csr(CSR_STIMECMPH, -1ul);
		write_csr(CSR_STIMECMP, lo);
		write_csr(CSR_STIMECMPH, hi);
#endif
	} else {
#if defined(CONFIG_64BIT)
		ecall(ECALL_WRTIME, val, 0, MTIMER_BASE);
#else
		ecall(ECALL_WRTIME, val, val >> 32, MTIMER_BASE);
#endif
	}
}

static void riscv_timer_isr(void *data)
{
	clear_csr(CSR_IE, IE_TIE);

	tevent_isr();
}

static void riscv_timer_enable(struct arch_timer *t)
{
	/*
	 * Register the timer INT
	 */
	t->irq = irq_register(t->dn, riscv_timer_isr, t);

	IMSG("TimerFRQ: %ld.%02ldMhz irq: %d Sstc: %d\n",
		t->frq / MICROSECS_PER_SEC,	(t->frq % MICROSECS_PER_SEC) * 100
		/ MICROSECS_PER_SEC, t->irq, sstc_supported());
}

static void riscv_timer_disable(struct arch_timer *t)
{
	/*
	 * Unregister the timer INT
	 */
	irq_unregister(t->irq);
}

static int __init riscv_timer_init(struct device_node *dn)
{
	struct device_node *clint = NULL;
	struct arch_timer *dst = &riscv_timer;
	struct arch_timer *t = dev_get_drvdata(&dn->dev);

	t->enable = riscv_timer_enable;
	t->disable = riscv_timer_disable;
	t->read_cycles = riscv_read_cycles;
	t->trigger_next = riscv_trigger_next;

	/*
	 * if Sstc extension does not present, just get the
	 * M-Mode clint-timer base address for forwarding
	 * the timer functions to M-Mode
	 */
	if (!sstc_supported()) {
		clint = of_find_compatible_node(NULL, "riscv,clint-timer");
		of_parse_io_resource(clint, 0, (unsigned long *)&t->base, NULL);
		of_property_read_u32(clint, "clock-frequency", &t->frq);
	}

	memcpy(dst, t, sizeof(struct arch_timer));

	dev_set_drvdata(&dn->dev, dst); /* update it */

	/* acts as system's ticktimer */
	set_ticktimer(dst);

	return 0;
}
DECLARE_TIMER(riscv_timer, "riscv,timer", riscv_timer_init);
