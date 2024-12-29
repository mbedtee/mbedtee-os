// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Arch Specific
 */

#include <of.h>
#include <trace.h>
#include <percpu.h>
#include <interrupt.h>

#include <arch-specific.h>

void arch_specific_init(void)
{
	/* reserves the SGI for aarch64 RPC callee */
#if defined(CONFIG_RPC)
	extern void smc_handler(void *regs);
	irq_register(NULL, thiscpu->sgi, smc_handler, NULL);
#endif

#if defined(CONFIG_REE)
#include <ree.h>
	setup_ree();
#endif
}
