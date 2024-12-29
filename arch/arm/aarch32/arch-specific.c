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
#if defined(CONFIG_REE)
#include <ree.h>
	setup_ree();
#endif
}
