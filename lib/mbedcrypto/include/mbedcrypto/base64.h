/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Base64 decoding utilities
 */

#ifndef _MBEDCRYPTO_BASE64_H
#define _MBEDCRYPTO_BASE64_H

#include <stddef.h>
#include <stdint.h>

/*
 * Decode base64-encoded data.
 *
 * dst:  output buffer (may be NULL to query required size).
 * dlen: capacity of dst.
 * olen: receives number of bytes written (or required).
 * src:  base64 input string.
 * slen: length of src in bytes.
 *
 * Returns 0 on success, -ERANGE if dst is too small, -EINVAL on bad input.
 */
int mbedcrypto_base64_decode(uint8_t *dst, size_t dlen, size_t *olen,
		const uint8_t *src, size_t slen);

#endif /* _MBEDCRYPTO_BASE64_H */
