/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Secondary CPUs PowerUp/PowerDown
 */

#ifndef _CPU_POWER_H
#define _CPU_POWER_H

#include <percpu.h>
#include <affinity.h>

/*
 * the arch/platform specific cpu-power ops
 */
struct cpu_pm_ops {
	int (*cpu_up)(unsigned int cpu);
	void (*cpu_down)(unsigned int cpu);
	void (*cpu_die)(void);
};

void cpu_pm_register(const struct cpu_pm_ops *ops);

#if CONFIG_NR_CPUS > 1
extern unsigned long secondary_entry;

void cpu_die(void);
void cpu_down(unsigned int cpu);
int cpu_up(unsigned int cpu, unsigned long pa);

#else

#define cpu_down(...) do {} while (0)
#define cpu_die(...) do {} while (0)
static inline int cpu_up(unsigned int cpu, unsigned long pa) {	return -1; }

#endif

/*
 * specify the hartid/mpid to be powered on
 */
extern unsigned long cpu_power_id;

/*
 * successfully powered on a cpu
 * runs on the current processor which is powered on
 */
static inline void cpu_set_online(void)
{
	cpu_affinity_set(cpus_online, percpu_id());
}

/*
 * error happened during cpu_up(), e.g. ENOMEM
 * runs on the current processor to be powered on
 */
static inline void cpu_set_error(void)
{
	cpu_affinity_set(cpus_error, percpu_id());
	cpu_die();
}

static inline bool cpu_online(unsigned int cpu)
{
	if (!VALID_CPUID(cpu))
		return false;

	return cpu_affinity_isset(cpus_online, cpu);
}

static inline bool cpu_error(unsigned int cpu)
{
	if (!VALID_CPUID(cpu))
		return false;

	return cpu_affinity_isset(cpus_error, cpu);
}

static inline void cpu_clear_online(void)
{
	cpu_affinity_clear(cpus_online, percpu_id());
}

static inline void cpu_clear_error(unsigned int cpu)
{
	if (VALID_CPUID(cpu))
		cpu_affinity_clear(cpus_error, cpu);
}

#endif
