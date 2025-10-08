// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Salix SoC - CA7x4 Secondary CPUs PowerUp/PowerDown
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
#include <secondary-cpu.h>

#include <power.h>

#if CONFIG_NR_CPUS > 1

unsigned long cpu_mpid;
static void *base_power;

#define CPU_MPID(x) (((unsigned long)(x) << 24) | mpid_of(x))

#define CA7_SW_CRTL_RST			BIT(10)
#define CA7_SW_SET_REQ			BIT(12)
#define CA7_SW_RST_REQ			BIT(16)
#define CA7_SW_CORERESET		BIT(20)

#define CA7_SW_PWRDOWN			BIT(16)
#define CA7_SLAVE_KEEP_RESET	BIT(31)
#define CA7_CPU_CTRL_REG		(base_power)
#define CA7_CPU_PWR_REG			(base_power + 4)

static void cpu_power_on(unsigned int cpu)
{
	void *reg = (void *)CA7_CPU_CTRL_REG;
	void *reg_pwr = (void *)CA7_CPU_PWR_REG;

	iowrite32((ioread32(reg_pwr) & (~CA7_SLAVE_KEEP_RESET)), reg_pwr);
	iowrite32((ioread32(reg) | CA7_SW_CRTL_RST), reg);
	iowrite32((ioread32(reg) | (CA7_SW_CORERESET << cpu)), reg);
	iowrite32((ioread32(reg) | (CA7_SW_RST_REQ << cpu)), reg);
	iowrite32((ioread32(reg) | (CA7_SW_SET_REQ << cpu)), reg);
	iowrite32((ioread32(reg_pwr) & (~(CA7_SW_PWRDOWN << cpu))), reg_pwr);
	iowrite32((ioread32(reg) & (~(CA7_SW_CORERESET << cpu))), reg);
	iowrite32((ioread32(reg) & (~(CA7_SW_RST_REQ << cpu))), reg);
	iowrite32((ioread32(reg) & (~(CA7_SW_SET_REQ << cpu))), reg);
}

static int ca7_cpu_up(unsigned int cpu)
{
	unsigned int intime = 10000;

	cpu_mpid = CPU_MPID(cpu);

	/* release the reset */
	cpu_power_on(cpu);

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

static void ca7_cpu_down(unsigned int cpu)
{
	void *reg = (void *)CA7_CPU_CTRL_REG;
	void *reg_pwr = (void *)CA7_CPU_PWR_REG;

	udelay(5000);

	iowrite32((ioread32(reg) | (CA7_SW_CORERESET << cpu)), reg);
	iowrite32((ioread32(reg) | (CA7_SW_RST_REQ << cpu)), reg);
	iowrite32((ioread32(reg_pwr) | (CA7_SW_PWRDOWN << cpu)), reg_pwr);
}

/*
 * runs on the processor to be powered off
 * unecessary, due to it will be powered off immediately
 */
static void ca7_cpu_die(void)
{
	/* SCTLR disable cache */
	asm volatile("dsb ishst\n"
				"mrc p15, 0, r0, c1, c0, 0\n"
				"bic r0, r0, #(0x04)\n"
				"mcr p15, 0, r0, c1, c0, 0\n"
				"isb"
		: : : "memory", "cc");

	flush_cache_louis();

	asm volatile("clrex" : : : "memory", "cc");

	/* ACTLR disable SMP */
	asm volatile("mrc p15, 0, r0, c1, c0, 1\n"
				"bic r0, r0, #(0x40)\n"
				"mcr p15, 0, r0, c1, c0, 1\n"
		: : : "memory", "cc");

	while (1)
		asm volatile("wfi");
}

static const struct cpu_pm_ops ca7_pm_ops = {
	.cpu_up = ca7_cpu_up,
	.cpu_down = ca7_cpu_down,
	.cpu_die = ca7_cpu_die
};

static int __init cpu_power_probe(struct device *dev)
{
	int ret = -1;
	unsigned long addr = 0;
	size_t bsize = 0;
	struct device_node *dn = NULL;

	cpu_pm_register(&ca7_pm_ops);

	dn = container_of(dev, struct device_node, dev);

	IMSG("init %s\n", dn->id.compat);

	ret = of_read_property_addr_size(dn, "reg", 0,
			&addr, &bsize);
	if (ret != 0) {
		EMSG("cpu-power dts\n");
		return ret;
	}

	base_power = iomap(addr, bsize);

	/* set the trampoline */
	memcpy(phys_to_virt(0x80000000), secondary_trampoline, 8);
	iowrite32(PA_OFFSET, phys_to_virt(0x80000004));

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
