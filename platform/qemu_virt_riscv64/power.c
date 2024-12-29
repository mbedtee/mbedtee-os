// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * QEMU virt RISCV64 - Secondary CPUs PowerUp/PowerDown
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

unsigned int cpu_hartid;

#define CPU_HARTID(x) (((unsigned int)(x) << 16) | hartid_of(x))

static int virt_riscv_cpu_up(unsigned int cpu)
{
	unsigned int intime = 10000;

	cpu_hartid = CPU_HARTID(cpu);

	do {
		/*
		 * #cpu_hartid is possibly updating by peer,
		 * make sure it's update to date for current CPU
		 */
		smp_mb();

		if (cpu_hartid != CPU_HARTID(cpu))
			break;

		udelay(5);
	} while (--intime);

	if (cpu_hartid == CPU_HARTID(cpu) || !intime)
		return -1;

	return 0;
}

/*
 * runs on the processor to be powered off
 */
static void virt_riscv_cpu_die(void)
{
	/*
	 * No Power Control of Processor on/off
	 * Just simulate the procedure
	 */

	flush_cache_louis();

	/* disable SMP */
}

static const struct cpu_pm_ops virt_riscv_pm_ops = {
	.cpu_up = virt_riscv_cpu_up,
	.cpu_die = virt_riscv_cpu_die
};

static int __init cpu_power_probe(struct device *dev)
{
	int ret = -1;
	unsigned long addr = 0;
	size_t bsize = 0;
	struct device_node *dn = NULL;

	cpu_pm_register(&virt_riscv_pm_ops);

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
