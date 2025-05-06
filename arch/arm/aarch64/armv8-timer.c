// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch64@ARMV8-A Generic Timer
 */

#include <io.h>
#include <of.h>
#include <str.h>
#include <kmap.h>
#include <timer.h>
#include <delay.h>
#include <trace.h>
#include <tevent.h>
#include <interrupt.h>

#define CNTCR	(0)
#define CNTCR_COUNTER_ENABLE (1) /* system counter enable */

#define GENERIC_TIMER_ENABLE (1) /* enable with int */
#define GENERIC_TIMER_DISABLE (2)
#define GENERIC_TIMER_MASK_INT (3) /* enable without int */

static struct arch_timer armv8_timer = {0};

static inline void reg_write(uint32_t val, uint32_t offset)
{
	if (armv8_timer.base)
		iowrite32(val, armv8_timer.base + offset);
}

static uint64_t armv8_read_cycles(void)
{
	uint64_t v0 = 0;

	asm volatile("isb\n"
				"mrs %0, cntpct_el0\n"
				"isb\n"
				: "=r" (v0)
				:
				: "memory", "cc");

	return v0;
}

static void armv8_trigger_next(uint64_t cycles)
{
	unsigned long en = GENERIC_TIMER_ENABLE;
	uint64_t val = cycles + armv8_read_cycles();

	/*
	 * set physical compare value
	 * enable timer with INT
	 */
	asm volatile (
		"msr cntps_cval_el1, %0\n"
		"msr cntps_ctl_el1, %1\n"
		"isb\n"
		:
		: "r" (val), "r" (en)
		: "memory", "cc");
}

static void armv8_timer_isr(void *data)
{
	tevent_isr();
}

static inline void armv8_set_cntfrq(
	unsigned long frq)
{
	smc_call(1, frq, 0, 0);
}

static void armv8_timer_enable(struct arch_timer *t)
{
	unsigned long v1 = GENERIC_TIMER_MASK_INT;
	unsigned long frq = 0;

	armv8_set_cntfrq(t->frq);

	asm volatile ("mrs %0, cntfrq_el0" : "=r" (frq):: "memory", "cc");

	assert(t->frq == frq);

	/*
	 * enable the system counter -- timer depends on the counter
	 */
	reg_write(CNTCR_COUNTER_ENABLE, CNTCR);

	/*
	 * EL0 is not allowed to access timer
	 */
	asm volatile (
		"msr cntkctl_el1, %0\n"
		:
		: "r" (0)
		: "memory", "cc");

	/*
	 * enable timer without INT
	 */
	asm volatile (
		"msr cntps_ctl_el1, %0\n"
		:
		: "r" (v1)
		: "memory", "cc");

	/*
	 * Register the timer INT
	 */
	t->irq = irq_register(t->dn, armv8_timer_isr, t);

	IMSG("TimerFRQ: %ld.%02ldMhz irq: %d\n", t->frq / MICROSECS_PER_SEC,
		(t->frq % MICROSECS_PER_SEC) * 100 / MICROSECS_PER_SEC, t->irq);
}

static void armv8_timer_disable(struct arch_timer *t)
{
	unsigned long v1 = GENERIC_TIMER_DISABLE;

	/*
	 * mask timer interrupt
	 */
	asm volatile (
		"msr cntps_ctl_el1, %0\n"
		:
		: "r" (v1)
		: "memory", "cc");

	/*
	 * Unregister the timer INT
	 */
	irq_unregister(t->irq);
}

static int __init armv8_timer_init(struct device_node *dn)
{
	struct arch_timer *dst = &armv8_timer;
	struct arch_timer *t = dev_get_drvdata(&dn->dev);

	t->enable = armv8_timer_enable;
	t->disable = armv8_timer_disable;
	t->read_cycles = armv8_read_cycles;
	t->trigger_next = armv8_trigger_next;

	memcpy(dst, t, sizeof(struct arch_timer));

	dev_set_drvdata(&dn->dev, dst); /* update it */

	/* acts as system's ticktimer */
	set_ticktimer(dst);

	return 0;
}
DECLARE_TIMER(armv8_timer, "arm,armv8-timer", armv8_timer_init);
