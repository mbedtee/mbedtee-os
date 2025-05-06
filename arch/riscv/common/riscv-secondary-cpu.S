/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * routines for secondary cpus
 */

#include <map.h>
#include "riscv-asm.h"

/*
 * Pick a hart which has lower id as boot hart,
 * a0 holds the return value
 */
.macro select_boot_hart
	delay_asm

	fence rw, rw
	li a0, -1

#if defined(CONFIG_RISCV_S_MODE)
	la a2, __supervisor_bmap
#else
	la a2, __machine_bmap
#endif

	lw a2, (a2)
	beqz a2, 22f

	move a0, zero
11:	andi a1, a2, 1
	bnez a1, 22f
	addi a0, a0, 1
	srli a2, a2, 1
	bnez a2, 11b
22: nop
.endm

/*
 * Wait for release, hartid is in a7
 * boot hart which has lower id will be automatic released
 */
FUNC_START secondary_cpu_wait
	/* hart-0 of course has the lowest hart id */
	beqz a7, __is_boot_hart

	select_boot_hart
	beq a7, a0, __is_boot_hart

#if (CONFIG_NR_CPUS > 1)
	la t0, cpu_power_id

__secondary_waiting:
	fence w, w
	lhu t1, (t0)
	bne a7, t1, __secondary_waiting

	/*
	 * cpu_power_id[31:16] contains the logic cpu-id
	 * logic cpu-id will be held/return in a7
	 */
	lhu a7, 2(t0)
	STR zero, (t0)
	fence rw, rw
	ret
#else
	wfi
	beqz zero, .
#endif

/* a7 now contains boot hart logic cpu-id - 0 */
__is_boot_hart:
	move a7, zero
	ret
FUNC_END secondary_cpu_wait

/*
 * this jumper only be used for the SoC which can't flexibly
 * assign the secondary CPUs' run entry to the '__memstart'
 *
 * copy this jumper (24-bytes) to the SoC's fix secondary-entry
 * and set '__memstart' to the '.dword' of this jumper (offset 0x10)
 * before release the secondary-cpu
 */
.align 3
FUNC_START secondary_trampoline
secondary_trampoline:
#if (CONFIG_NR_CPUS > 1)
	la t0, 1f
	nop
	LDR ra, (t0)
	ret
1:	.dword 0
#else
1:	wfi
	beqz zero, 1b
#endif
FUNC_END secondary_trampoline

.data
.balign BYTES_PER_LONG, 0
.global cpu_power_id
cpu_power_id:
	.fill 1, BYTES_PER_LONG, 0
