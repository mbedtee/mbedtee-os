/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Cache handling
 */


#ifndef _CACHEOPS_H
#define _CACHEOPS_H

/*
 * flush all levels dcache by set/way
 */
void flush_cache_all(void);

/*
 * flush level of unification inner shareable
 * dcache by set/way
 */
void flush_cache_louis(void);

/*
 * Invalid whole instruction cache
 */
void flush_icache_all(void);

#endif
