/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Cache flush and invalidate API, by VA
 */

#ifndef _CACHE_H
#define _CACHE_H

#include <stddef.h>

void flush_cache(void *va, size_t size);

void invalidate_cache(void *va, size_t size);

#endif
