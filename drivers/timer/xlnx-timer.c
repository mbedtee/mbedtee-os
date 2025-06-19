// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * xilinx xps-timer
 */

#include <of.h>
#include <io.h>
#include <str.h>
#include <kmap.h>
#include <timer.h>
#include <trace.h>
#include <tevent.h>
#include <interrupt.h>

/* timer-0 */
#define R_TCSR     (0 << 2)
#define R_TLR      (1 << 2)
#define R_TCR      (2 << 2)
/* timer-1 */
#define R_TCSR1    (4 << 2)
#define R_TLR1     (5 << 2)
#define R_TCR1     (6 << 2)

#define TCSR_MDT   (1 << 0)
#define TCSR_UDT   (1 << 1)
#define TCSR_GENT  (1 << 2)
#define TCSR_CAPT  (1 << 3)
#define TCSR_ARHT  (1 << 4)
#define TCSR_LOAD  (1 << 5)
#define TCSR_ENIT  (1 << 6)
#define TCSR_ENT   (1 << 7)
#define TCSR_TINT  (1 << 8)
#define TCSR_PWMA  (1 << 9)
#define TCSR_ENALL (1 << 10)

static struct arch_timer xlnx_timer = {0};

static struct xlnx_timer_cnt {
	/* last cycle stamp - nanoseconds precision */
	uint64_t cycles_stamp;
	/* total time since PoR - nanoseconds precision */
	struct timespec time;

	/* last cycle stamp 32/64-bit */
	uint32_t cyclelast32;
	uint64_t cyclelast64;
} __tick64[CONFIG_NR_CPUS] = {{0}};

static inline void reg_write(uint32_t val, long offset)
{
	iowrite32(val, xlnx_timer.base + offset);
}

static inline uint32_t reg_read(long offset)
{
	return ioread32(xlnx_timer.base + offset);
}

static uint64_t xlnx_timer_read_cycles(void)
{
	unsigned long flags = 0;
	uint32_t cycles_new = 0, tmp_cycles = 0;
	struct xlnx_timer_cnt *c = NULL;

	local_irq_save(flags);

	c = &__tick64[percpu_id()];
	cycles_new = reg_read(R_TCR1);
	tmp_cycles = cycles_new - c->cyclelast32;
	c->cyclelast64 += tmp_cycles;
	c->cyclelast32 = cycles_new;

	local_irq_restore(flags);

	return c->cyclelast64;
}

static void xlnx_timer_trigger_next(uint64_t cycles)
{
	/* loading value to timer reg */
	reg_write(cycles, R_TLR);

	/* load the initial value */
	reg_write(TCSR_LOAD, R_TCSR);

	reg_write(TCSR_TINT | TCSR_ENIT | TCSR_ENT |
		TCSR_ARHT | TCSR_UDT, R_TCSR);
}

static void xlnx_timer_isr(void *data)
{
	reg_write(reg_read(R_TCSR), R_TCSR);

	tevent_isr();
}

static void xlnx_timer_setup(struct arch_timer *t)
{
	/* stop 0 */
	reg_write(reg_read(R_TCSR) & ~TCSR_ENT, R_TCSR);

	/* stop 1 */
	reg_write(reg_read(R_TCSR1) & ~TCSR_ENT, R_TCSR1);

	/* start counting 1 without interrupt */
	reg_write(TCSR_TINT | TCSR_ENT | TCSR_ARHT, R_TCSR1);
}

static void xlnx_timer_enable(struct arch_timer *t)
{
	xlnx_timer_setup(t);

	/*
	 * Register the timer INT
	 */
	t->irq = irq_register(t->dn, xlnx_timer_isr, t);

	IMSG("TimerFRQ: %ld.%02ldMhz irq: %d\n", t->frq / MICROSECS_PER_SEC,
		(t->frq % MICROSECS_PER_SEC) * 100 / MICROSECS_PER_SEC, t->irq);
}

static void xlnx_timer_disable(struct arch_timer *t)
{
	/* stop 0 */
	reg_write(reg_read(R_TCSR) & ~TCSR_ENT, R_TCSR);

	irq_unregister(t->irq);
}

static int __init xlnx_timer_init(struct device_node *dn)
{
	struct arch_timer *dst = &xlnx_timer;
	struct arch_timer *t = dev_get_drvdata(&dn->dev);

	t->enable = xlnx_timer_enable;
	t->disable = xlnx_timer_disable;
	t->read_cycles = xlnx_timer_read_cycles;
	t->trigger_next = xlnx_timer_trigger_next;

	memcpy(dst, t, sizeof(struct arch_timer));

	dev_set_drvdata(&dn->dev, dst); /* update it */

	/* acts as system's ticktimer */
	set_ticktimer(dst);

	return 0;
}
DECLARE_TIMER(xlnx_timer, "xlnx,xps-timer", xlnx_timer_init);
