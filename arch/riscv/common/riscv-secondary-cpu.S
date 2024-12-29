/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * routines for secondary cpus
 */

#include <map.h>
#include "riscv-asm.h"

/*
 * Wait for release, hartid is a0
 */
FUNC_START secondary_cpu_wait
#if (CONFIG_NR_CPUS > 1)
	la t0, cpu_hartid
1:	fence w, w
	lhu t1, (t0)
	bne a0, t1, 1b
	/* cpu_hartid[31:16] contains the logic cpu-id
	 transfer cpu-id to a0 */
	lhu a0, 2(t0)
	sw zero, (t0)
	fence rw, rw
	ret
#else
1:	wfi
	beqz zero, 1b
#endif
FUNC_END secondary_cpu_wait

/*
 * this jumper only be used for the SoC which can't flexibly
 * assign the secondary CPUs' run entry to the '__memstart'
 *
 * copy this jumper (12 or 24-bytes) to the SoC's fix secondary-entry
 * and set '__memstart' to the '.word' of this jumper
 * before release the secondary-cpu
 */
FUNC_START secondary_trampoline
#if (CONFIG_NR_CPUS > 1)
	la t0, 1f
	LDR ra, (t0)
	ret
1:	.word -1
#else
1:	wfi
	beqz zero, 1b
#endif
FUNC_END secondary_trampoline
