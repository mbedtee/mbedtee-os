// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Secondary CPUs PowerUp/PowerDown
 */

#include <io.h>
#include <of.h>
#include <cpu.h>
#include <mem.h>
#include <mmu.h>
#include <ipi.h>
#include <kmap.h>
#include <trace.h>
#include <delay.h>
#include <timer.h>
#include <thread.h>
#include <driver.h>
#include <kthread.h>
#include <cacheops.h>
#include <interrupt.h>
#include <affinity.h>

#include <power.h>

#define INVALID_PM_CPU(x) (!VALID_CPUID(x) || !(x))

struct cpu_affinity cpus_online[1] = {0};
struct cpu_affinity cpus_error[1] = {0};

#if CONFIG_NR_CPUS > 1

static SPIN_LOCK(onlock);
static struct cpu_pm_ops pm_ops = {NULL};
unsigned long secondary_entry;

static void poll_cpu(unsigned int cpu)
{
	unsigned int intime = 15000, error = false;

	do {
		read_time(NULL);

		/*
		 * -- sync the time --
		 * make sure the time is update to date
		 * and visible to the peer #cpu
		 */
		smp_mb();

		if (cpu_online(cpu))
			break;

		if (cpu_error(cpu)) {
			error = true;
			break;
		}

		usleep(50);
	} while (--intime);

	if (error)
		EMSG("CPU%d: PowerOn Error\n", cpu);
	else if (intime)
		IMSG("CPU%d: Powered on\n", cpu);
	else
		EMSG("CPU%d: PowerOn Timeout\n", cpu);
}

static void __cpu_up(void *data)
{
	int cpu = (intptr_t)data;
	int error = false;

	flush_cache_louis();

	if (pm_ops.cpu_up)
		error = pm_ops.cpu_up(cpu);

	if (error)
		EMSG("CPU%d: PowerOn Error\n", cpu);
	else
		poll_cpu(cpu);
}

int cpu_up(unsigned int cpu, unsigned long pa)
{
	int tid = -1;
	unsigned long flags = 0;
	struct sched_param p = {SCHED_PRIO_MAX};

	if (INVALID_PM_CPU(cpu) || (!pa))
		return -EINVAL;

	if (in_interrupt())
		IMSG("Powering on CPU%d@0x%lx\n", cpu, pa);
	else
		IMSG("Powering on CPU%d\n", cpu);

	spin_lock_irqsave(&onlock, flags);

	if (cpu_online(cpu)) {
		IMSG("CPU%d: Already Online??\n", cpu);
		spin_unlock_irqrestore(&onlock, flags);
		return -EEXIST;
	}

	cpu_clear_error(cpu);

	secondary_entry = pa;

	spin_unlock_irqrestore(&onlock, flags);

	if (in_interrupt()) {
		tid = kthread_create_on(__cpu_up,
				(void *)(intptr_t)cpu, 0, "cpu_up");
		if (tid < 0) {
			IMSG("failed to create thd for %d ret %d\n", cpu, tid);
			return tid;
		}
		sched_setscheduler(tid, SCHED_FIFO, &p);
		sched_ready(tid);
		/* run the __cpu_up() ASAP */
		ipi_call_sched(0);
	} else {
		__cpu_up((void *)(intptr_t)cpu);
	}

	return 0;
}

void cpu_down(unsigned int cpu)
{
	unsigned int intime = 12000;
	unsigned long flags = 0;

	IMSG("Removing Power of CPU%d\n", cpu);

	if (INVALID_PM_CPU(cpu))
		return;

	spin_lock_irqsave(&onlock, flags);

	while (cpu_online(cpu) && (--intime))
		udelay(50);

	if (pm_ops.cpu_down)
		pm_ops.cpu_down(cpu);

	IMSG("CPU%d Powered down\n", cpu);

	spin_unlock_irqrestore(&onlock, flags);
}

/*
 * runs on the processor to be powered off
 */
void cpu_die(void)
{
	local_irq_disable();

	timer_down();
	ipi_down();
	sched_down();
	worker_down();

	irq_migrating();
	sched_migrating();
	tevent_migrating();/* shall be the last one */

	flush_cache_louis();

	cpu_clear_online();

	isb();
	/*
	 * make sure the updates is visible
	 * to whole system before it goes to die
	 */
	smp_mb();

	/* never return */
	if (pm_ops.cpu_die)
		pm_ops.cpu_die();
}

void cpu_pm_register(const struct cpu_pm_ops *ops)
{
	memcpy(&pm_ops, ops, sizeof(*ops));
}

#endif
