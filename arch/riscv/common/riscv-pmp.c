// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * RISC-V PMP (Physical Memory Protection) setup.
 */

#include <of.h>
#include <cpu.h>
#include <mem.h>
#include <trace.h>
#include <sections.h>

/*
 * Set PMP entries to enforce memory protections.
 * Called on each CPU from arch_specific_init().
 *
 * S-mode: delegates to M-mode via ecall (only M-mode can write PMP CSRs).
 * M-mode: directly writes PMP CSRs; the Locked (L) bit makes entries apply
 * to all privilege levels including M-mode, providing code/data integrity.
 *
 * Using PMP TOR mode: pmpaddr[i-1] <= y < pmpaddr[i]
 * pmp0: 0 ~ mem_base         (IO below DRAM, RW, Locked)
 * pmp1: mem_base ~ _start    (DRAM below .text, RWX, Locked)
 * pmp2: _start ~ __TEXT_END  (.text, RX, Locked)
 * pmp3: __TEXT_END ~ __RODATA_END  (.rodata, R, Locked)
 * pmp4: rest                 (RWX, Locked)
 */
void riscv_pmp_init(void)
{
#if defined(CONFIG_RISCV_S_MODE)
	ecall(ECALL_SET_PMP, mem_base, 0, 0);
#else
	extern char _start[];

#define _PMP_TOR    0x08UL   /* Top-Of-Range address matching */
#define _PMP_LOCK   0x80UL   /* Locked: applies to M-mode too */
#define _PMP_R      0x01UL
#define _PMP_W      0x02UL
#define _PMP_X      0x04UL

	unsigned long pmpcfg = 0;

	/* pmp0: IO region (0 ~ mem_base); OFF if mem_base == 0 */
	write_csr(pmpaddr0, mem_base >> 2);
	if (mem_base)
		pmpcfg |= (_PMP_TOR | _PMP_LOCK | _PMP_R | _PMP_W) << 0;

	/* pmp1: DRAM below .text (mem_base ~ _start) */
	write_csr(pmpaddr1, (unsigned long)_start >> 2);
	pmpcfg |= (_PMP_TOR | _PMP_LOCK | _PMP_R | _PMP_W | _PMP_X) << 8;

	/* pmp2: .text (RX) */
	write_csr(pmpaddr2, __text_end() >> 2);
	pmpcfg |= (_PMP_TOR | _PMP_LOCK | _PMP_R | _PMP_X) << 16;

	/* pmp3: .rodata (R) */
	write_csr(pmpaddr3, __rodata_end() >> 2);
	pmpcfg |= (_PMP_TOR | _PMP_LOCK | _PMP_R) << 24;

	/* pmp4: rest (RWX) */
	write_csr(pmpaddr4, -1UL);

#if defined(CONFIG_64BIT)
	pmpcfg |= (_PMP_TOR | _PMP_LOCK | _PMP_R | _PMP_W | _PMP_X) << 32;
	write_csr(pmpcfg0, pmpcfg);
#else
	write_csr(pmpcfg0, pmpcfg);
	write_csr(pmpcfg1, _PMP_TOR | _PMP_LOCK | _PMP_R | _PMP_W | _PMP_X);
#endif

#endif
}
