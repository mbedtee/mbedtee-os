// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Minimal ASN.1 DER encode / decode
 *
 * Only what is needed for DSA / ECDSA signature encoding:
 *   SEQUENCE { INTEGER r, INTEGER s }
 */

#include <string.h>

#include <mbedcrypto/asn1.h>

/* ------------------------------------------------------------------ */
/*  DER write helpers (backwards from *p toward start)                */
/* ------------------------------------------------------------------ */

int mbedcrypto_asn1_write_tag(uint8_t **p, const uint8_t *start,
		uint8_t tag)
{
	if (*p - start < 1)
		return -EINVAL;

	*--(*p) = tag;
	return 1;
}

int mbedcrypto_asn1_write_len(uint8_t **p, const uint8_t *start,
		size_t len)
{
	if (len < 0x80) {
		if (*p - start < 1)
			return -EINVAL;
		*--(*p) = len;
		return 1;
	}

	if (len <= 0xFF) {
		if (*p - start < 2)
			return -EINVAL;
		*--(*p) = len;
		*--(*p) = 0x81;
		return 2;
	}

	/* len <= 0xFFFF - sufficient for any signature we produce */
	if (*p - start < 3)
		return -EINVAL;
	*--(*p) = len;
	*--(*p) = len >> 8;
	*--(*p) = 0x82;
	return 3;
}

int mbedcrypto_asn1_write_bn(uint8_t **p, const uint8_t *start,
		const struct mbedcrypto_bignum *X)
{
	int ret = 0;
	size_t len = 0;
	int written = 0;

	len = mbedcrypto_bn_byte_count(X);

	/* Value is zero: encode as single 0x00 byte */
	if (len == 0)
		len = 1;

	if ((size_t)(*p - start) < len)
		return -EINVAL;

	/* Write the integer value (big-endian unsigned) */
	*p -= len;
	if ((ret = mbedcrypto_bn_to_binary(X, *p, len)) != 0)
		return ret;

	written += len;

	/* DER integers are signed; if the high bit is set, prepend 0x00 */
	if ((**p) & 0x80) {
		if (*p <= start)
			return -EINVAL;
		*--(*p) = 0x00;
		written++;
		len++;
	}

	/* Write length */
	ret = mbedcrypto_asn1_write_len(p, start, len);
	if (ret < 0)
		return ret;
	written += ret;

	/* Write tag */
	ret = mbedcrypto_asn1_write_tag(p, start, MBEDCRYPTO_ASN1_INTEGER);
	if (ret < 0)
		return ret;
	written += ret;

	return written;
}

/*
 * Write raw bytes backwards from *p toward start.
 * Returns number of bytes written, or negative errno.
 */
int mbedcrypto_asn1_write_raw(uint8_t **p, const uint8_t *start,
		const uint8_t *data, size_t len)
{
	if ((size_t)(*p - start) < len)
		return -EINVAL;

	*p -= len;
	memcpy(*p, data, len);
	return len;
}

/*
 * Write a DER NULL (05 00) backwards.
 * Returns 2, or negative errno.
 */
int mbedcrypto_asn1_write_null(uint8_t **p, const uint8_t *start)
{
	int ret = 0;

	ret = mbedcrypto_asn1_write_len(p, start, 0);
	if (ret < 0)
		return ret;

	ret = mbedcrypto_asn1_write_tag(p, start, 0x05);
	if (ret < 0)
		return ret;

	return 2;
}

/*
 * Write a DER OID (tag 06 + length + value bytes) backwards.
 * Returns total bytes written, or negative errno.
 */
int mbedcrypto_asn1_write_oid(uint8_t **p, const uint8_t *start,
		const uint8_t *oid, size_t oid_len)
{
	int ret, written = 0;

	ret = mbedcrypto_asn1_write_raw(p, start, oid, oid_len);
	if (ret < 0)
		return ret;
	written += ret;

	ret = mbedcrypto_asn1_write_len(p, start, oid_len);
	if (ret < 0)
		return ret;
	written += ret;

	ret = mbedcrypto_asn1_write_tag(p, start, MBEDCRYPTO_ASN1_OID);
	if (ret < 0)
		return ret;
	written += ret;

	return written;
}

/* ------------------------------------------------------------------ */
/*  DER read helpers                                                  */
/* ------------------------------------------------------------------ */

/*
 * Read a DER length from *p. On success *p is advanced past the
 * length field and *len is set.
 */
static int asn1_get_len(const uint8_t **p, const uint8_t *end,
		size_t *len)
{
	if (*p >= end)
		return -EBADMSG;

	if ((**p & 0x80) == 0) {
		*len = *(*p)++;
		return 0;
	}

	switch (**p & 0x7F) {
	case 1:
		if (end - *p < 2)
			return -EBADMSG;
		*len = (*p)[1];
		*p += 2;
		return 0;

	case 2:
		if (end - *p < 3)
			return -EBADMSG;
		*len = ((size_t)(*p)[1] << 8) | (*p)[2];
		*p += 3;
		return 0;

	default:
		return -EBADMSG; /* lengths > 64 KiB not expected */
	}
}

int mbedcrypto_asn1_read_tag(const uint8_t **p, const uint8_t *end,
		size_t *len, uint8_t expected_tag)
{
	if (*p >= end)
		return -EBADMSG;

	if (**p != expected_tag)
		return -EBADMSG;

	(*p)++;
	return asn1_get_len(p, end, len);
}

int mbedcrypto_asn1_read_bn(const uint8_t **p, const uint8_t *end,
		struct mbedcrypto_bignum *X)
{
	int ret = 0;
	size_t len = 0;

	ret = mbedcrypto_asn1_read_tag(p, end, &len,
			MBEDCRYPTO_ASN1_INTEGER);
	if (ret != 0)
		return ret;

	if (*p + len > end)
		return -EBADMSG;

	/* Skip leading zero byte added for sign */
	if (len > 1 && (*p)[0] == 0x00) {
		(*p)++;
		len--;
	}

	ret = mbedcrypto_bn_from_binary(X, *p, len);
	*p += len;
	return ret;
}
