// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * QEMU IMX7D - Secondary CPUs PowerUp/PowerDown
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

#define SRC_A7RCR0		1	/* reset core */
#define SRC_A7RCR1		2	/* enable core */
#define SRC_GPR3		31	/* store the entry point */

static struct imx7src {unsigned int r[40];} *imx7src = NULL;

#define CPU_MPID(x) (((unsigned long)(x) << 24) | mpid_of(x))

static int arm_cpu_up(unsigned int cpu)
{
	unsigned int intime = 10000;

	imx7src->r[SRC_A7RCR1] |= BIT(cpu);

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

static void arm_cpu_down(unsigned int cpu)
{
	udelay(5000);

	/*
	 * IMX7D has the Power Control of Processor on/off
	 * Just powered it off, no need to use Monitor/WFE to simulate the procedure
	 */
	imx7src->r[SRC_A7RCR1] &= ~ BIT(cpu);
}

/*
 * runs on the processor to be powered off
 */
static void arm_cpu_die(void)
{
	smc_call(2, 0, 0, 0);
}

static const struct cpu_pm_ops arm_pm_ops = {
	.cpu_up = arm_cpu_up,
	.cpu_down = arm_cpu_down,
	.cpu_die = arm_cpu_die
};

static int __init cpu_power_probe(struct device *dev)
{
	struct device_node *dn = NULL;

	cpu_pm_register(&arm_pm_ops);

	dn = container_of(dev, struct device_node, dev);

	IMSG("init %s\n", dn->id.compat);

	imx7src = of_iomap(dn, 0);
	if (imx7src == NULL) {
		WMSG("cpu-power dts\n");
		return -EINVAL;
	}

	/* store the entry point */
	imx7src->r[SRC_GPR3] = PA_OFFSET;

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
