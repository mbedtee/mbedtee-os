/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>
 * cache init
 */

#include <cacheops.h>
#include <riscv-asm.h>

/*
 * Andes CCTL ecall: a0 = ECALL_CCTL_CMD, a1 = cctl command
 */
.macro cctl_ecall cmd
	la t0, __riscv_features
	LDR t0, (t0)
	li t1, RISCV_FEAT_ANDES
	and t0, t0, t1
	beqz t0, 1f
#if defined(CONFIG_RISCV_S_MODE)
	li a0, ECALL_CCTL_CMD
	li a1, \cmd
	ecall
#else
	li t1, \cmd
	csrw 0x7cc, t1
#endif
1:
.endm

/*
 * T-Head xtheadcmo "all" cache operations.
 * Encodings (R-type, opcode=0x0b, rs1=x0, rd=x0):
 *   th.dcache.ciall: 0x0230000b  (Clean & Invalidate all D-cache)
 *   th.dcache.call:  0x0210000b  (Clean all D-cache)
 *   th.dcache.iall:  0x0020000b  (Invalidate all D-cache)
 *   th.sync.s:       0x0190000b  (Synchronize)
 */
.macro thead_cmo_op insn
	la t0, __riscv_features
	LDR t0, (t0)
	li t1, RISCV_FEAT_THEAD
	and t0, t0, t1
	beqz t0, 2f
	.long \insn
	.long 0x0190000b /* th.sync.s */
2:
.endm

FUNC_START flush_cache_all
	cctl_ecall CCTL_L1D_WBINVAL_ALL
	thead_cmo_op 0x0230000b /* th.dcache.ciall */
	ret
FUNC_END flush_cache_all

FUNC_START flush_cache_louis
	cctl_ecall CCTL_L1D_WB_ALL
	thead_cmo_op 0x0210000b /* th.dcache.call */
	ret
FUNC_END flush_cache_louis

FUNC_START invalidate_dcache_l1
	cctl_ecall CCTL_L1D_INVAL_ALL
	thead_cmo_op 0x0020000b /* th.dcache.iall */
	ret
FUNC_END invalidate_dcache_l1

FUNC_START invalidate_dcache_l2
	ret
FUNC_END invalidate_dcache_l2
