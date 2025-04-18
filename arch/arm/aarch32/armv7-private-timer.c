// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32@ARMV7-A Private Timer
 */

#include <io.h>
#include <of.h>
#include <str.h>
#include <kmap.h>
#include <timer.h>
#include <trace.h>
#include <tevent.h>
#include <interrupt.h>

#define PRIVATE_TIMER_LOAD (0x600)
#define PRIVATE_TIMER_COUNTER (0x604)
#define PRIVATE_TIMER_CTRL (0x608)
#define PRIVATE_TIMER_STATUS (0x60C)

#define GLOBAL_TIMER_FREERUN_COUNTER1 (0x204)
#define GLOBAL_TIMER_FREERUN_COUNTER0 (0x200)
#define GLOBAL_TIMER_CTRL (0x208)
#define SCU_NSAC_CTRL (0x54)

#define PRIVATE_TIMER_ENABLE (5) /* enable with int */
#define PRIVATE_TIMER_DISABLE (0)
#define PRIVATE_TIMER_MASK_INT (1) /* enable without int */

static struct arch_timer armv7_timer = {0};

static inline void reg_write(uint32_t val, uint32_t offset)
{
	iowrite32(val, armv7_timer.base + offset);
}

static inline uint32_t reg_read(uint32_t offset)
{
	return ioread32(armv7_timer.base + offset);
}

static uint64_t armv7_read_cycles(void)
{
	uint32_t v1 = 0, v0 = 0;

	do {
		v1 = reg_read(GLOBAL_TIMER_FREERUN_COUNTER1);
		v0 = reg_read(GLOBAL_TIMER_FREERUN_COUNTER0);
	} while (v1 != reg_read(GLOBAL_TIMER_FREERUN_COUNTER1));

	return ((uint64_t)v1 << 32) | v0;
}

static void armv7_timer_isr(void *data)
{
	if (reg_read(PRIVATE_TIMER_STATUS)) {
		reg_write(1, PRIVATE_TIMER_STATUS);
		tevent_isr();
	}
	reg_write(PRIVATE_TIMER_ENABLE, PRIVATE_TIMER_CTRL);
}

static void armv7_trigger_next(uint64_t cycles)
{
	reg_write(cycles, PRIVATE_TIMER_COUNTER);
}

static void armv7_timer_enable(struct arch_timer *t)
{
	reg_write(0, PRIVATE_TIMER_LOAD);
	reg_write(PRIVATE_TIMER_DISABLE, PRIVATE_TIMER_CTRL);
	reg_write(-1ul, PRIVATE_TIMER_COUNTER);
	reg_write(PRIVATE_TIMER_ENABLE, PRIVATE_TIMER_CTRL);

	/*
	 * enable the global timer for freerun counter
	 * disable NS access to private/global timers
	 */
	reg_write(1, GLOBAL_TIMER_CTRL);
	reg_write(0x000, SCU_NSAC_CTRL);

	/*
	 * Register the timer INT
	 */
	t->irq = irq_of_register(t->dn, t->hwirq, armv7_timer_isr, t);

	IMSG("TimerFRQ: %ld.%02ldMhz hwirq: %d\n", t->frq / MICROSECS_PER_SEC,
		(t->frq % MICROSECS_PER_SEC) * 100 / MICROSECS_PER_SEC, t->hwirq);
}

static void armv7_timer_disable(struct arch_timer *t)
{
	reg_write(PRIVATE_TIMER_MASK_INT, PRIVATE_TIMER_CTRL);

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
DECLARE_TIMER(armv7_timer, "arm,armv7-private-timer", armv7_timer_init);
