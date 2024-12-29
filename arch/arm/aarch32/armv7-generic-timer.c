// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32@ARMV7-A Generic Timer
 */

#include <of.h>
#include <str.h>
#include <timer.h>
#include <trace.h>
#include <delay.h>
#include <tevent.h>
#include <interrupt.h>

#define GENERIC_TIMER_ENABLE (1) /* enable with int */
#define GENERIC_TIMER_DISABLE (2)
#define GENERIC_TIMER_MASK_INT (3) /* enable without int */

static struct arch_timer armv7_timer = {0};

static uint64_t armv7_read_cycles(void)
{
	uint32_t v1 = 0, v0 = 0;

	asm volatile("isb\n"
				"mrrc p15, 0, %0, %1, c14\n"
				"isb\n"
				: "=r" (v0), "=r" (v1)
				:
				: "memory", "cc");

	return ((uint64_t)v1 << 32) | v0;
}

static void armv7_trigger_next(uint64_t cycles)
{
	uint32_t en = GENERIC_TIMER_ENABLE;
	uint64_t val = cycles + armv7_read_cycles();

	/*
	 * set physical compare value
	 * enable timer with INT
	 */
	asm volatile (
		"mcrr p15, 2, %0, %1, c14\n"
		"mcr p15, 0, %2, c14, c2, 1\n"
		"isb\n"
		:
		: "r" (val), "r" (val >> 32), "r" (en)
		: "memory", "cc");
}

static void armv7_set_frq(struct arch_timer *t)
{
	unsigned long frq = t->frq;

	/*
	 * set frequency @ CNTFRQ Secure PL1 Only
	 */
	asm volatile (
		"mcr p15, 0, %0, c14, c0, 0\n"
		"isb\n"
		:
		: "r" (frq)
		: "memory", "cc");

	asm volatile (
		"mrc p15, 0, %0, c14, c0, 0\n"
		"isb\n"
		: "=r" (frq)
		:
		: "memory", "cc");

	assert(frq == t->frq);
}

static void armv7_timer_isr(void *data)
{
	tevent_isr();
}

static void armv7_timer_enable(struct arch_timer *t)
{
	unsigned long v1 = GENERIC_TIMER_MASK_INT, v2 = INT_MAX;

	armv7_set_frq(t);

	/*
	 * physical compare value @ CNTP_CVAL
	 * enable timer @ CNTP_CTL without INT
	 */
	asm volatile (
		"mcrr p15, 2, %0, %1, c14\n"
		"mcr p15, 0, %2, c14, c2, 1\n"
		:
		: "r" (v1), "r" (v2), "r" (v1)
		: "memory", "cc");

	/*
	 * Register the timer INT
	 */
	t->irq = irq_of_register(t->dn, t->hwirq, armv7_timer_isr, t);

	IMSG("TimerFRQ: %ld.%02ldMhz hwirq: %d\n", t->frq / MICROSECS_PER_SEC,
		(t->frq % MICROSECS_PER_SEC) * 100 / MICROSECS_PER_SEC, t->hwirq);
}

static void armv7_timer_disable(struct arch_timer *t)
{
	unsigned long v1 = GENERIC_TIMER_MASK_INT;

	/*
	 * mask timer interrupt @ CNTP_CTL
	 */
	asm volatile (
		"mcr p15, 0, %0, c14, c2, 1\n"
		:
		: "r" (v1)
		: "memory", "cc");

	/*
	 * Unregister the timer INT
	 */
	irq_unregister(t->irq);
}

static int __init armv7_timer_init(struct device_node *dn)
{
	struct arch_timer *dst = &armv7_timer;
	struct arch_timer *t = dev_get_drvdata(&dn->dev);

	t->enable = armv7_timer_enable;
	t->disable = armv7_timer_disable;
	t->read_cycles = armv7_read_cycles;
	t->trigger_next = armv7_trigger_next;

	memcpy(dst, t, sizeof(struct arch_timer));

	dev_set_drvdata(&dn->dev, dst); /* update it */

	/* acts as system's ticktimer */
	set_ticktimer(dst);

	return 0;
}
DECLARE_TIMER(armv7_timer, "arm,armv7-generic-timer", armv7_timer_init);
