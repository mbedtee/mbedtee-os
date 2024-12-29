/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Cache handling for AArch32@ARMV7-A based SoC
 */

#ifndef _CACHEOPS_H
#define _CACHEOPS_H

#include <barrier.h>

/*
 * flush the icache(inv)
 * flush all levels dcache by set/way
 */
void flush_cache_all(void);

/*
 * flush the icache(inv)
 * flush level of unification inner shareable
 * dcache by set/way
 */
void flush_cache_louis(void);

/*
 * Invalid whole instruction cache
 */
void flush_icache_all(void);

#endif
