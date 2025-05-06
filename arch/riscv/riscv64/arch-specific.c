// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Arch Specific
 */

#include <of.h>
#include <trace.h>
#include <power.h>
#include <percpu.h>
#include <interrupt.h>

#include <arch-specific.h>

void arch_specific_init(void)
{
	int cpu = 0;

	/* only CPU 0 does this, up the other CPUs */
	if (percpu_id() == 0) {
		for_each_possible_cpu(cpu)
			cpu_up(cpu, -1);
	}
}
