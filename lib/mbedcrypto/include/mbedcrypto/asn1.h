/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Minimal ASN.1 DER encode / decode
 *
 * Supports just enough for DSA / ECDSA signature encoding:
 *   SEQUENCE { INTEGER r, INTEGER s }
 *
 * Write functions work backwards from end of buffer (DER convention).
 */

#ifndef _MBEDCRYPTO_ASN1_H
#define _MBEDCRYPTO_ASN1_H

#include <mbedcrypto/bignum.h>

/* ASN.1 tag values. */
#define MBEDCRYPTO_ASN1_INTEGER            0x02
#define MBEDCRYPTO_ASN1_BIT_STRING         0x03
#define MBEDCRYPTO_ASN1_OCTET_STRING       0x04
#define MBEDCRYPTO_ASN1_OID                0x06
#define MBEDCRYPTO_ASN1_SEQUENCE           0x30

/*
 * Write a bignum as a DER INTEGER into [start..p).
 * *p points one past the last byte written; on success it is
 * decremented to the first byte of the INTEGER.
 * Returns number of bytes written, or negative errno.
 */
int mbedcrypto_asn1_write_bn(uint8_t **p, const uint8_t *start,
		const struct mbedcrypto_bignum *X);

/*
 * Write a DER length field.
 * Returns bytes written or negative errno.
 */
int mbedcrypto_asn1_write_len(uint8_t **p, const uint8_t *start,
		size_t len);

/*
 * Write a DER tag byte.
 * Returns 1 or negative errno.
 */
int mbedcrypto_asn1_write_tag(uint8_t **p, const uint8_t *start,
		uint8_t tag);

/*
 * Write raw bytes (pre-encoded) backwards into [start..p).
 * Returns bytes written or negative errno.
 */
int mbedcrypto_asn1_write_raw(uint8_t **p, const uint8_t *start,
		const uint8_t *data, size_t len);

/*
 * Write a DER NULL (05 00) backwards.
 * Returns 2 or negative errno.
 */
int mbedcrypto_asn1_write_null(uint8_t **p, const uint8_t *start);

/*
 * Write a DER OID (tag 06, length, value bytes) backwards.
 * Returns total bytes written or negative errno.
 */
int mbedcrypto_asn1_write_oid(uint8_t **p, const uint8_t *start,
		const uint8_t *oid, size_t oid_len);

/*
 * Read and verify a DER tag at *p.  Advances *p past the tag and
 * length, sets *len to the content length.
 * Returns 0 on success, -EBADMSG / -EINVAL on error.
 */
int mbedcrypto_asn1_read_tag(const uint8_t **p, const uint8_t *end,
		size_t *len, uint8_t expected_tag);

/*
 * Read a DER INTEGER into a bignum.
 * Advances *p past the INTEGER.
 */
int mbedcrypto_asn1_read_bn(const uint8_t **p, const uint8_t *end,
		struct mbedcrypto_bignum *X);

#endif /* _MBEDCRYPTO_ASN1_H */
