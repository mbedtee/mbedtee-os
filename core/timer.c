// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#include <of.h>
#include <str.h>
#include <kmap.h>
#include <timer.h>
#include <trace.h>
#include <delay.h>
#include <tevent.h>
#include <interrupt.h>

struct arch_timer *ticktimer;

static LIST_HEAD(timers);

static struct percpu_tick {
	/* last cycle stamp - nanoseconds precision */
	uint64_t cycles_stamp;
	/* total time since PoR - nanoseconds precision */
	struct timespec time;
} __percpu_tick[CONFIG_NR_CPUS] = {0};

static inline struct percpu_tick *percpu_tick(void)
{
	return &__percpu_tick[percpu_id()];
}

static void sync_time(void)
{
	int cpu = percpu_id();
	struct percpu_tick *pt = &__percpu_tick[cpu];
	struct timespec *ts0 = &__percpu_tick[0].time;

	if (cpu == 0) {
		pt->cycles_stamp = read_cycles();
	} else {
		pt->time = *ts0;
		while (timespeccmp(&pt->time, ts0, ==))
			smp_mb(); /* CPU0 updates is visible to current CPU */

		pt->time = *ts0;
		pt->cycles_stamp = read_cycles();
	}

	read_time(NULL);
}

void read_time(struct timespec *val)
{
	uint64_t cycles_diff = 0;
	uint64_t cycles_stamp = 0;
	struct percpu_tick *pt = NULL;
	unsigned long flags = 0;
	struct timespec diff;

	if (!ticktimer)
		return;

	local_irq_save(flags);

	pt = percpu_tick();

	cycles_stamp = read_cycles();

	cycles_diff = sub_cycles(cycles_stamp, pt->cycles_stamp);
	cycles_to_time(cycles_diff, &diff);
	timespecadd(&pt->time, &diff, &pt->time);
	pt->cycles_stamp = cycles_stamp;

	if (val)
		*val = pt->time;

	local_irq_restore(flags);
}

static int timer_suspend(void *data)
{
	struct arch_timer *t = NULL;

	read_time(NULL);

	list_for_each_entry(t, &timers, node)
		t->disable(t);

	return 0;
}

static int timer_resume(void *data)
{
	struct arch_timer *t = NULL;

	list_for_each_entry(t, &timers, node)
		t->enable(t);

	sync_time();
	trigger_next(usecs_to_cycles(10));

	return 0;
}
DECLARE_STR_CORE(timer, timer_suspend, timer_resume, NULL);

/*
 * For CPU Hot-Plug (percpu)
 * Force turn off the percpu ticktimer or other percpu timers
 */
void timer_down(void)
{
	timer_suspend(NULL);
}

/*
 * init/enable the ticktimer or other timers
 */
void timer_init(void)
{
	int cpu = percpu_id();
	struct arch_timer *t = ticktimer;

	list_for_each_entry(t, &timers, node) {
		/*
		 * enable the percpu timers
		 */
		if (!t->is_global)
			t->enable(t);
		/*
		 * enable the GLOBAL (not percpu) timers
		 */
		else if (cpu == 0)
			t->enable(t);
	}

	sync_time();
}

static void __init timer_calc_const(struct arch_timer *t)
{
	t->cycles_per_msecs = t->frq / 1000UL;
	t->cycles_per_usecs = t->cycles_per_msecs / 1000UL;

	t->cycles_per_nsecs = (1ULL << 20) * t->cycles_per_usecs / 1000UL;

	t->nsecs_per_cycles = (1ULL << 20) * NANOSECS_PER_SEC / t->frq;

	t->usecs_per_cycles = (1ULL << 20) / t->cycles_per_usecs;
}

static int __init timer_parse_dts(struct device_node *dn,
	struct arch_timer *t)
{
	int ret = -1;
	unsigned long base = 0;

	t->dn = dn;

	ret = of_property_read_u32(dn, "interrupts", &t->hwirq);
	if (ret) {
		EMSG("interrupts not found @ %s\n", dn->id.name);
		return ret;
	}

	ret = of_property_read_u32(dn, "clock-frequency", &t->frq);
	if (ret) {
		EMSG("clock-frequency not found @ %s\n", dn->id.name);
		return ret;
	}

	ret = of_read_property_addr_size(dn, "reg", 0, &base, &t->size);
	if (ret == 0)
		t->base = iomap(base, t->size);

	/* the FRQ shall always fast than 1Mega-Hz */
	if (t->frq < MICROSECS_PER_SEC) {
		EMSG("clk frequency not support\n");
		return -ENOTSUP;
	}

	return 0;
}

/*
 * parse the DTS, init the timer callbacks
 */
void __init timer_early_init(void)
{
	int ret = -1;
	struct of_compat_init *start = NULL;
	struct of_compat_init *end = NULL;
	struct of_compat_init *oci = NULL;
	struct device_node *dn = NULL;
	struct arch_timer timerdesc, *t = NULL;

	start = __timer_init_start();
	end = __timer_init_end();

	for (oci = start; oci < end; oci++) {
		dn = of_find_compatible_node(NULL, oci->compat);
		if (dn == NULL)
			continue;

		memset(&timerdesc, 0, sizeof(timerdesc));

		ret = timer_parse_dts(dn, &timerdesc);
		if (ret)
			continue;

		dev_set_drvdata(&dn->dev, &timerdesc);

		ret = oci->init(dn);
		if (ret != 0) {
			EMSG("failed to initialize %s - %d\n", oci->compat, ret);
			continue;
		}

		/* declared timers should update the timer_desc */
		t = dev_get_drvdata(&dn->dev);
		list_add_tail(&t->node, &timers);

		timer_calc_const(t);
	}
}
