// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>
 * Arch Specific
 */

#include <of.h>
#include <cpu.h>
#include <trace.h>
#include <power.h>
#include <percpu.h>
#include <interrupt.h>

#include <arch-specific.h>

void arch_specific_init(void)
{
	int cpu = 0;

	if (percpu_id() == 0) {
		/* up the other CPUs */
		for_each_possible_cpu(cpu)
			cpu_up(cpu, -1);
	}

	riscv_pmp_init();
}
