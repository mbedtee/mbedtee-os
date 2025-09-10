/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Cache handling for AArch64 based SoC
 */

#ifndef _CACHEOPS_H
#define _CACHEOPS_H

#ifdef __cplusplus
extern "C" {
#endif

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
 * Invalidate whole instruction cache
 */
void flush_icache_all(void);

#ifdef __cplusplus
}
#endif

#endif
