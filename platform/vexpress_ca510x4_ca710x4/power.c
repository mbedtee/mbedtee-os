// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * FVP VEXPRESS CA510x4_CA710x4 Secondary CPUs PowerUp/PowerDown
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

#include <power.h>

#if CONFIG_NR_CPUS > 1

static void *base_power;

#define CPU_MPID(x) (((unsigned long)(x) << 40) | mpid_of(x))

static int ca510_ca710_cpu_up(unsigned int cpu)
{
	unsigned int intime = 10000;

	/* set Base_PowerController PPONR ? - unused */
	/* iowrite32(mpid_of(cpu), base_power + 4); */

	cpu_power_id = CPU_MPID(cpu);

	do {
		asm volatile("sev" : : : "memory", "cc");

		/*
		 * #cpu_power_id is possibly updating by peer,
		 * make sure it's update to date for current CPU
		 */
		smp_mb();

		if (cpu_power_id != CPU_MPID(cpu))
			break;

		udelay(5);
	} while (--intime);

	if (cpu_power_id == CPU_MPID(cpu) || !intime)
		return -1;

	return 0;
}

/*
 * runs on the processor to be powered off
 */
static void ca510_ca710_cpu_die(void)
{
	/* set Base_PowerController PPOFFR ? - unused */
	/* iowrite32(mpid_of(percpu_id()), base_power); */

	/*
	 * Just use Monitor/WFE to simulate the procedure
	 */
	smc_call(2, 0, 0, 0);
}

static const struct cpu_pm_ops ca510_ca710_pm_ops = {
	.cpu_up = ca510_ca710_cpu_up,
	.cpu_die = ca510_ca710_cpu_die
};

static int __init cpu_power_probe(struct device *dev)
{
	struct device_node *dn = NULL;

	cpu_pm_register(&ca510_ca710_pm_ops);

	dn = container_of(dev, struct device_node, dev);

	IMSG("init %s\n", dn->id.compat);

	base_power = of_iomap(dn, 0);
	if (base_power == NULL) {
		WMSG("cpu-power dts\n");
		return -EINVAL;
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
