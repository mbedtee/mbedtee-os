// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * ARM CA7x2 QEMU AST2600 - Secondary CPUs PowerUp/PowerDown
 */

#include <io.h>
#include <of.h>
#include <mem.h>
#include <mmu.h>
#include <cpu.h>
#include <kmap.h>
#include <trace.h>
#include <delay.h>
#include <timer.h>
#include <driver.h>
#include <cacheops.h>
#include <interrupt.h>

#include <power.h>

#if CONFIG_NR_CPUS > 1

unsigned int cpu_mpid;

#define CPU_MPID(x) (((unsigned long)(x) << 24) | mpid_of(x))

static int arm_cpu_up(unsigned int cpu)
{
	unsigned int intime = 10000;

	cpu_mpid = CPU_MPID(cpu);

	do {
		asm volatile("sev" : : : "memory", "cc");

		/*
		 * #cpu_mpid is possibly updating by peer,
		 * make sure it's update to date for current CPU
		 */
		smp_mb();

		if (cpu_mpid != CPU_MPID(cpu))
			break;
		udelay(5);
	} while (--intime);

	if (cpu_mpid == CPU_MPID(cpu) || !intime)
		return -1;

	return 0;
}

/*
 * runs on the processor to be powered off
 */
static void arm_cpu_die(void)
{
	/*
	 * No Power Control of Processor on/off
	 * Just use Monitor/WFE to simulate the procedure
	 */
	smc_call(2, 0, 0, 0);
}

static const struct cpu_pm_ops arm_pm_ops = {
	.cpu_up = arm_cpu_up,
	.cpu_die = arm_cpu_die
};

static int __init cpu_power_probe(struct device *dev)
{
	int ret = -1;
	unsigned long addr = 0;
	size_t bsize = 0;
	struct device_node *dn = NULL;

	cpu_pm_register(&arm_pm_ops);

	dn = container_of(dev, struct device_node, dev);

	IMSG("init %s\n", dn->id.compat);

	ret = of_read_property_addr_size(dn, "reg", 0,
			&addr, &bsize);
	if (ret != 0) {
		WMSG("cpu-power dts\n");
		return ret;
	}

	return 0;
}

static const struct of_device_id cpu_power_desc[] = {
	{.name = "cpu-power", .compat = "module,cpu-power"},
	{},
};

static const struct device_driver of_cpu_power = {
	.name = "cpu-power-ctrl",
	.probe = cpu_power_probe,
	.of_match_table = cpu_power_desc,
};

module_arch(of_cpu_power);

#endif
