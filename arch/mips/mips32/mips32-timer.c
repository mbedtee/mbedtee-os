// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 CP0 Timer
 */

#include <of.h>
#include <str.h>
#include <timer.h>
#include <trace.h>
#include <tevent.h>
#include <interrupt.h>

static struct arch_timer mips32_timer = {0};

static struct mips32_cp0_cnt{
	/* last cycle stamp - nanoseconds precision */
	uint64_t cycles_stamp;
	/* total time since PoR - nanoseconds precision */
	struct timespec time;

	/* last cycle stamp 32/64-bit */
	uint32_t cyclelast32;
	uint64_t cyclelast64;
} __tick64[CONFIG_NR_CPUS] = {{0}};

static uint64_t mips32_read_cycles(void)
{
	unsigned long flags = 0;
	uint32_t cycles_new = 0, tmp_cycles = 0;
	struct mips32_cp0_cnt *c = NULL;

	local_irq_save(flags);

	c = &__tick64[percpu_id()];
	cycles_new = read_cp0_register(C0_COUNT);
	tmp_cycles = cycles_new - c->cyclelast32;
	c->cyclelast64 += tmp_cycles;
	c->cyclelast32 = cycles_new;

	local_irq_restore(flags);

	return c->cyclelast64;
}

static void mips32_timer_isr(void *data)
{
	tevent_isr();
}

static void mips32_trigger_next(uint64_t cycles)
{
	uint32_t val = read_cp0_register(C0_COUNT);

	/*
	 * set physical compare value
	 */
	write_cp0_register(C0_COMPARE, cycles + val);
}

static inline uint32_t mips32_timer_ipti(void)
{
	uint32_t v = 0;

	/*
	 * Get Timer Interrupt Number
	 */
	asm volatile("mfc0 %0, $12, 1\n"
				 "srl %0, 29\n"
				 : "=r" (v)
				 :
				 : "memory", "cc");
	return v;
}

static void mips32_timer_enable(struct arch_timer *t)
{
	uint32_t ipti = mips32_timer_ipti();

	if (ipti != t->hwirq)
		return;

	/*
	 * Register the tick timer INT
	 */
	t->irq = irq_register(NULL, t->hwirq, mips32_timer_isr, t);

	IMSG("TimerFRQ: %ld.%02ldMhz hwirq: %d\n", t->frq / MICROSECS_PER_SEC,
		(t->frq % MICROSECS_PER_SEC) * 100 / MICROSECS_PER_SEC, t->hwirq);
}

static void mips32_timer_disable(struct arch_timer *t)
{
	/*
	 * Unregister the timer INT
	 */
	irq_unregister(t->irq);
}

static int __init mips32_timer_init(struct device_node *dn)
{
	struct arch_timer *dst = &mips32_timer;
	struct arch_timer *t = dev_get_drvdata(&dn->dev);

	t->enable = mips32_timer_enable;
	t->disable = mips32_timer_disable;
	t->read_cycles = mips32_read_cycles;
	t->trigger_next = mips32_trigger_next;

	memcpy(dst, t, sizeof(struct arch_timer));

	dev_set_drvdata(&dn->dev, dst); /* update it */

	/* acts as system's ticktimer */
	set_ticktimer(dst);

	return 0;
}
DECLARE_TIMER(mips32_timer, "mips32,cp0-timer", mips32_timer_init);
