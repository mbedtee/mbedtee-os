/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Constant-time memory comparison
 */

#ifndef _MBEDTEE_MEMCMP_H
#define _MBEDTEE_MEMCMP_H

#include <stddef.h>

/*
 * Constant-time memory comparison.
 * Returns 0 if the two buffers are identical, non-zero otherwise.
 * Always traverses all bytes regardless of mismatches,
 * preventing timing side-channel attacks.
 *
 * Unlike standard memcmp(), the return value does not indicate
 * ordering (less-than / greater-than). Use this function only
 * for equality checks in security-sensitive contexts such as
 * MAC verification, tag comparison, and nonce validation.
 */
int mbedtee_memcmp(const void *a, const void *b, size_t len);

#endif
