// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * main() routine to initialize the Kernel
 */

#include <cpu.h>
#include <ipi.h>
#include <page.h>
#include <string.h>
#include <mem.h>
#include <mmu.h>
#include <percpu.h>
#include <thread.h>
#include <device.h>
#include <kmalloc.h>
#include <sections.h>
#include <interrupt.h>
#include <version.h>
#include <build.h>
#include <ctx.h>
#include <vma.h>
#include <of.h>
#include <str.h>
#include <timer.h>
#include <delay.h>
#include <kvma.h>
#include <kthread.h>
#include <workqueue.h>
#include <trace.h>
#include <tasklet.h>
#include <platform.h>
#include <sched.h>
#include <ktime.h>
#include <debugfs.h>

#include <arch-specific.h>
#include <stackprotector.h>
#include <generated/autoconf.h>

#if defined(CONFIG_UART)
#include <uart.h>
#endif

#include <power.h>

static void __init kern_info(void)
{
	struct tm t;
	time_t sec = strtoul(BUILD_TIME_SEC, NULL, 10);
	long nsec = strtoul(BUILD_TIME_NSEC, NULL, 10);

	set_systime(sec, nsec);

	time2date(sec, &t);

	IMSG("Product: %s\n", PRODUCT_NAME);
	IMSG("Version: %s\n", PRODUCT_VERSION);
	IMSG("Compiler : %s-gcc\n", TOOLCHAIN_TARGET);
	IMSG("Compiler version: %d.%d.%d\n",
		__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
	IMSG("Newlib version: %s\n", _NEWLIB_VERSION);

	IMSG("Build Tag - %s\n", BUILD_TAG);
	IMSG("Build Time - %04d-%02d-%02d %02d:%02d:%02d.%03ld\n",
		t.tm_year+1900, t.tm_mon+1, t.tm_mday,
		t.tm_hour, t.tm_min, t.tm_sec,
		nsec / MICROSECS_PER_SEC);

	mem_info();
}

static void __rest_init_once(void)
{
	static bool _restinit;

	if (_restinit)
		return;

	_restinit = true;

	modules_init();

	kmalloc_post_init();
}

static void __rest_init(void *d)
{
	local_irq_disable();

	workqueue_init();

	/* only CPU 0 does this, once */
	__rest_init_once();

	arch_specific_init();

	if (!IS_ENABLED(CONFIG_REE) || IS_ENABLED(CONFIG_RISCV)) {
		/* only CPU 0 does this, up the other CPUs */
		if (percpu_id() == 0)
			for (int i = 1; i < CONFIG_NR_CPUS; i++)
				cpu_up(i, -1);
	} else {
		/* wait the REE startup */
		if (percpu_id() != 0)
			msleep(100);
	}

	sched_cpu_online();
}

static void rest_init(void)
{
	int id = -1;
	struct sched_param p = {.sched_priority =
		SCHED_PRIO_MAX};

	id = kthread_create_on(__rest_init,
			NULL, percpu_id(), "init");
	if (id < 0) {
		EMSG("kthread_create failed %d\n", id);
		cpu_set_error();
	}

	sched_setscheduler(id, SCHED_FIFO, &p);

	sched_ready(id);

	/*
	 * launch the scheduler
	 */
	schedule();

	panic("launch scheduler failed\n");
}

static void init(void)
{
	percpu_info();
	percpu_init();

	tevents_init();
	timer_init();

	ipi_init();

	sched_init();
}

static void __init early_init_once(void)
{
	assert(of_fdt_early_init() == 0);
	assert(kmalloc_early_init() == 0);
	assert(mem_early_init() == 0);
	assert(of_fdt_init() == 0);
	assert(cpu_data_init() == 0);
	assert(map_kern() == 0);

	timer_early_init();

#if defined(CONFIG_UART)
	uart_early_init();
#endif

	irq_init();

	early_init();

	kern_info();

	mem_init();
}

int __nosprot main(void)
{
	static bool _earinit;

	/*
	 * set the current with a dummy thread,
	 * to avoid get_current() - return NULL
	 */
	set_current(kthread());

	/* check warm-boot flag */
	str_resume();

	/*
	 * early_init_once() performs the
	 * global initialization for all CPUs
	 * but which is executed only on Cluster0.CPU0 once.
	 *
	 * all secondary cores shall not call it.
	 */
	if (_earinit == false) {
		_earinit = true;

		kproc_init();

		/* set stack protector guard val */
		__stack_chk_guard_set();

		early_init_once();
	}

	init();

	rest_init();

	return 0;
}
