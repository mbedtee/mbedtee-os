/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * cache init
 */

#include <riscv-asm.h>

FUNC_START flush_cache_all
	ret
FUNC_END flush_cache_all

FUNC_START flush_cache_louis
	ret
FUNC_END flush_cache_louis

FUNC_START invalidate_dcache_l1
	ret
FUNC_END invalidate_dcache_l1

FUNC_START invalidate_dcache_l2
	ret
FUNC_END invalidate_dcache_l2
