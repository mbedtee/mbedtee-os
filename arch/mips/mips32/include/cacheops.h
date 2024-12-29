/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Cache handling for MIPS32 based SoC
 */

#ifndef _CACHEOPS_H
#define _CACHEOPS_H

/*
 * local core only
 * Invalid whole instruction cache
 */
void local_flush_icache_all(void);

/* currently no SMP for mips32 */
#define flush_icache_all local_flush_icache_all

#endif
