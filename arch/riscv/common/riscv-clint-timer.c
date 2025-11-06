// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV Clint Timer (M-mode)
 */

#include <of.h>
#include <io.h>
#include <str.h>
#include <kmap.h>
#include <timer.h>
#include <trace.h>
#include <tevent.h>
#include <interrupt.h>

#define CLINT_TIMER_CMP_REG	0x0000
#define CLINT_TIMER_VAL_REG	0x7ff8

static struct arch_timer riscv_timer = {0};

static inline void reg_write(unsigned long val, long offset)
{
	iowritel(val, riscv_timer.base + offset);
}

static inline unsigned long reg_read(long offset)
{
	return ioreadl(riscv_timer.base + offset);
}

static uint64_t riscv_read_cycles(void)
{
	if (!riscv_timer.base)
		return -1;

#if defined(CONFIG_64BIT)
	return reg_read(CLINT_TIMER_VAL_REG);
#else
	uint32_t v1 = 0, v0 = 0;

	do {
		v1 = reg_read(CLINT_TIMER_VAL_REG + BYTES_PER_LONG);
		v0 = reg_read(CLINT_TIMER_VAL_REG);
	} while (v1 != reg_read(CLINT_TIMER_VAL_REG + BYTES_PER_LONG));

	return ((uint64_t)v1 << 32) | v0;
#endif
}

static void riscv_trigger_next(uint64_t cycles)
{
	long offset = percpu_hartid() * sizeof(uint64_t);

	offset += CLINT_TIMER_CMP_REG;

#if defined(CONFIG_64BIT)
	reg_write(riscv_read_cycles() + cycles, offset);
#else
	uint64_t val = riscv_read_cycles() + cycles;
	uint32_t hi = val >> 32;
	uint32_t lo = val;

	reg_write(-1ul, offset + BYTES_PER_INT);
	reg_write(lo, offset);
	reg_write(hi, offset + BYTES_PER_INT);
#endif

	set_csr(CSR_IE, IE_TIE);
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

	IMSG("TimerFRQ: %ld.%02ldMhz irq: %d\n", t->frq / MICROSECS_PER_SEC,
		(t->frq % MICROSECS_PER_SEC) * 100 / MICROSECS_PER_SEC, t->irq);
}

static void riscv_timer_disable(struct arch_timer *t)
{
	irq_unregister(t->irq);
}

static int __init riscv_timer_init(struct device_node *dn)
{
	struct arch_timer *dst = &riscv_timer;
	struct arch_timer *t = dev_get_drvdata(&dn->dev);

	t->enable = riscv_timer_enable;
	t->disable = riscv_timer_disable;
	t->read_cycles = riscv_read_cycles;
	t->trigger_next = riscv_trigger_next;

	memcpy(dst, t, sizeof(struct arch_timer));

	dev_set_drvdata(&dn->dev, dst); /* update it */

	/* acts as system's ticktimer */
	set_ticktimer(dst);

	return 0;
}
DECLARE_TIMER(riscv_timer, "riscv,clint-timer", riscv_timer_init);
