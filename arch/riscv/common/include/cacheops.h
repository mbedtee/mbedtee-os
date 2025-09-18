/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>
 * Cache handling
 */

#ifndef _CACHEOPS_H
#define _CACHEOPS_H

/*
 * Andes CCTL command values for mcctlcommand CSR (0x7cc)
 * Used by M-mode set/way operations (ecall) and S-mode VA-range operations.
 */
#define CCTL_L1D_VA_INVAL    0   /* L1 D-cache invalidate by VA */
#define CCTL_L1D_VA_WB       1   /* L1 D-cache writeback by VA */
#define CCTL_L1D_VA_WBINVAL  2   /* L1 D-cache writeback + invalidate by VA */
#define CCTL_L1D_WBINVAL_ALL 6   /* L1 D-cache writeback + invalidate all */
#define CCTL_L1D_WB_ALL      7   /* L1 D-cache writeback all */
#define CCTL_L1I_INVAL_ALL   16  /* L1 I-cache invalidate all */
#define CCTL_L1D_INVAL_ALL   23  /* L1 D-cache invalidate all */

/* Andes CCTL S/U-mode CSRs */
#define UCCTLBEGINADDR       0x80B
#define UCCTLCOMMAND         0x80C

/* Andes cache line size (bytes) */
/* Andes cache line size (bytes) - default, overridden by DTS */
#define ANDES_CACHELINE_SIZE 32

#if !defined(__ASSEMBLY__)

#ifdef __cplusplus
extern "C" {
#endif

#include <riscv-tlb.h>

/*
 * Cache line size in bytes, read from DTS "cache-line-size" property.
 * Initialized to 64 as default, updated during cpu_data_init().
 */
extern unsigned long riscv_cacheline_size;

/*
 * flush all levels dcache by set/way
 */
void flush_cache_all(void);

/*
 * flush level of unification inner shareable
 * dcache by set/way
 */
void flush_cache_louis(void);

#ifdef __cplusplus
}
#endif

#endif /* !__ASSEMBLY__ */

#endif
