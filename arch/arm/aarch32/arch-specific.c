// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Arch Specific
 */

#include <of.h>
#include <ree.h>
#include <trace.h>
#include <sleep.h>
#include <power.h>
#include <percpu.h>
#include <interrupt.h>

#include <arch-specific.h>

void arch_specific_init(void)
{
	int cpu = 0;

	if (IS_ENABLED(CONFIG_REE) && is_security_extn_ena()) {
		setup_ree();
		/* wait the REE startup */
		if (percpu_id() != 0)
			msleep(100);
	} else {
		/* only CPU 0 does this, up the other CPUs */
		if (percpu_id() == 0) {
			for_each_possible_cpu(cpu)
				cpu_up(cpu, -1);
		}
	}
}
