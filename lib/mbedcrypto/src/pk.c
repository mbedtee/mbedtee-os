// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Public key / private key DER encoding and decoding
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <mbedcrypto/ecp.h>
#include <mbedcrypto/asn1.h>
#include <mbedcrypto/pk.h>

/*
 * Decode/Import an RSA public key from DER encoding.
 *
 * Supports two formats:
 *   1) SubjectPublicKeyInfo (SPKI):
 *      SEQUENCE {
 *        SEQUENCE { OID, NULL }   -- AlgorithmIdentifier
 *        BIT STRING {             -- 0x03
 *          0x00                   -- unused bits
 *          SEQUENCE {             -- RSAPublicKey
 *            INTEGER N,
 *            INTEGER E
 *          }
 *        }
 *      }
 *
 *   2) PKCS#1 RSAPublicKey (bare):
 *      SEQUENCE {
 *        INTEGER N,
 *        INTEGER E
 *      }
 */
int mbedcrypto_pk_decode_rsa_pubkey_der(struct mbedcrypto_rsa_ctx *rsa,
		const uint8_t *buf, size_t buflen)
{
	const uint8_t *p = buf;
	const uint8_t *end = buf + buflen;
	size_t len = 0;
	int ret = 0;

	if (!rsa || !buf || buflen == 0)
		return -EINVAL;

	/* Outer SEQUENCE */
	ret = mbedcrypto_asn1_read_tag(&p, end, &len,
			MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret != 0)
		return ret;

	end = p + len;

	/*
	 * Detect format: SPKI starts with a SEQUENCE
	 * (AlgorithmIdentifier), bare RSAPublicKey starts
	 * with an INTEGER (modulus).
	 */
	if (*p == MBEDCRYPTO_ASN1_SEQUENCE) {
		/* Skip AlgorithmIdentifier SEQUENCE */
		ret = mbedcrypto_asn1_read_tag(&p, end, &len,
				MBEDCRYPTO_ASN1_SEQUENCE);
		if (ret != 0)
			return ret;
		p += len; /* skip OID + optional NULL */

		/* BIT STRING wrapping the RSAPublicKey */
		ret = mbedcrypto_asn1_read_tag(&p, end, &len,
				MBEDCRYPTO_ASN1_BIT_STRING);
		if (ret != 0)
			return ret;
		if (*p != 0x00)
			return -EBADMSG;
		p++; /* skip unused-bits byte */

		/* Inner RSAPublicKey SEQUENCE */
		ret = mbedcrypto_asn1_read_tag(&p, end, &len,
				MBEDCRYPTO_ASN1_SEQUENCE);
		if (ret != 0)
			return ret;
	}

	/* Import modulus N */
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->N);
	if (ret != 0)
		return ret;

	/* Import exponent E */
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->E);
	return ret;
}

/*
 * Decode/Import a PKCS#1 RSAPrivateKey from DER encoding.
 *
 * RSAPrivateKey ::= SEQUENCE {
 *   version           INTEGER (0),
 *   modulus           INTEGER,   -- N
 *   publicExponent    INTEGER,   -- E
 *   privateExponent   INTEGER,   -- D
 *   prime1            INTEGER,   -- P
 *   prime2            INTEGER,   -- Q
 *   exponent1         INTEGER,   -- DP = D mod (P-1)
 *   exponent2         INTEGER,   -- DQ = D mod (Q-1)
 *   coefficient       INTEGER    -- QP = Q^-1 mod P
 * }
 */
int mbedcrypto_pk_decode_rsa_privkey_der(struct mbedcrypto_rsa_ctx *rsa,
		const uint8_t *buf, size_t buflen)
{
	const uint8_t *p = buf;
	const uint8_t *end = buf + buflen;
	struct mbedcrypto_bignum version;
	size_t len = 0;
	int ret = 0;

	if (!rsa || !buf || buflen == 0)
		return -EINVAL;

	/* Outer SEQUENCE */
	ret = mbedcrypto_asn1_read_tag(&p, end, &len,
			MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret != 0)
		return ret;

	end = p + len;

	/* Version (must be 0 for two-prime RSA) */
	mbedcrypto_bn_init(&version);
	ret = mbedcrypto_asn1_read_bn(&p, end, &version);
	mbedcrypto_bn_cleanup(&version);
	if (ret != 0)
		return ret;

	/* N, E, D, P, Q, DP, DQ, QP */
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->N);
	if (ret != 0)
		return ret;
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->E);
	if (ret != 0)
		return ret;
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->D);
	if (ret != 0)
		return ret;
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->P);
	if (ret != 0)
		return ret;
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->Q);
	if (ret != 0)
		return ret;
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->DP);
	if (ret != 0)
		return ret;
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->DQ);
	if (ret != 0)
		return ret;
	ret = mbedcrypto_asn1_read_bn(&p, end, &rsa->QP);

	return ret;
}

/*
 * Decode/Import an EC public key from an uncompressed point.
 *
 * Uncompressed format: 04 || X || Y
 * Each coordinate is (group byte-length) bytes.
 */
int mbedcrypto_pk_decode_ec_pubkey(struct mbedcrypto_ecp_keypair *key,
		int grp_id, const uint8_t *buf, size_t buflen)
{
	size_t coord_len = 0;
	int ret = 0;

	if (!key || !buf || buflen == 0)
		return -EINVAL;

	/* Import the curve parameters */
	ret = mbedcrypto_ecp_load_group(&key->grp, grp_id);
	if (ret != 0)
		return ret;

	coord_len = (key->grp.pbits + 7) / 8;

	/* Expect 04 || X || Y */
	if (buf[0] != 0x04 || buflen != 1 + 2 * coord_len)
		return -EBADMSG;

	/* Read X coordinate */
	ret = mbedcrypto_bn_from_binary(&key->Q.X, buf + 1, coord_len);
	if (ret != 0)
		return ret;

	/* Read Y coordinate */
	ret = mbedcrypto_bn_from_binary(&key->Q.Y,
			buf + 1 + coord_len, coord_len);
	if (ret != 0)
		return ret;

	/* Set Z = 1 (affine) */
	ret = mbedcrypto_bn_set_word(&key->Q.Z, 1);
	return ret;
}

/*
 * Decode/Import an EC private key from a raw big-endian scalar.
 */
int mbedcrypto_pk_decode_ec_privkey(struct mbedcrypto_ecp_keypair *key,
		int grp_id, const uint8_t *buf, size_t buflen)
{
	int ret = 0;

	if (!key || !buf || buflen == 0)
		return -EINVAL;

	/* Import the curve parameters */
	ret = mbedcrypto_ecp_load_group(&key->grp, grp_id);
	if (ret != 0)
		return ret;

	/* Import private scalar d */
	ret = mbedcrypto_bn_from_binary(&key->d, buf, buflen);
	return ret;
}

/*
 * Decode/Import DH parameters from DER encoding.
 *
 * DHParameter ::= SEQUENCE {
 *   prime             INTEGER,  -- P
 *   base              INTEGER   -- G
 * }
 */
int mbedcrypto_pk_decode_dh_params_der(struct mbedcrypto_dh_ctx *ctx,
		const uint8_t *buf, size_t buflen)
{
	const uint8_t *p = buf;
	const uint8_t *end = buf + buflen;
	size_t len = 0;
	int ret = 0;

	if (!ctx || !buf || buflen == 0)
		return -EINVAL;

	/* Outer SEQUENCE */
	ret = mbedcrypto_asn1_read_tag(&p, end, &len,
			MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret != 0)
		return ret;

	end = p + len;

	/* Import Prime P */
	ret = mbedcrypto_asn1_read_bn(&p, end, &ctx->P);
	if (ret != 0)
		return ret;

	/* Import Generator G */
	ret = mbedcrypto_asn1_read_bn(&p, end, &ctx->G);
	return ret;
}

/* ------------------------------------------------------------------ */
/* DER encoding (write) functions                                     */
/* ------------------------------------------------------------------ */

/*
 * Encode RSA public key as PKCS#1 RSAPublicKey DER.
 *
 * RSAPublicKey ::= SEQUENCE {
 *   modulus         INTEGER,   -- N
 *   publicExponent  INTEGER    -- E
 * }
 *
 * Returns total DER size (> 0) written to buf, or negative errno.
 */
int mbedcrypto_pk_encode_rsa_pubkey_der(struct mbedcrypto_rsa_ctx *rsa,
		uint8_t *buf, size_t buflen)
{
	uint8_t *p = buf + buflen;
	int ret, len = 0;

	if (!rsa || !buf || buflen == 0)
		return -EINVAL;

	/* Write backwards: E, then N */
	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->E);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->N);
	if (ret < 0)
		return ret;
	len += ret;

	/* SEQUENCE header */
	ret = mbedcrypto_asn1_write_len(&p, buf, len);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_tag(&p, buf, MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret < 0)
		return ret;
	len += ret;

	memmove(buf, p, len);
	return len;
}

/*
 * Encode RSA private key as PKCS#1 RSAPrivateKey DER.
 *
 * RSAPrivateKey ::= SEQUENCE {
 *   version           INTEGER (0),
 *   modulus           INTEGER,   -- N
 *   publicExponent    INTEGER,   -- E
 *   privateExponent   INTEGER,   -- D
 *   prime1            INTEGER,   -- P
 *   prime2            INTEGER,   -- Q
 *   exponent1         INTEGER,   -- DP
 *   exponent2         INTEGER,   -- DQ
 *   coefficient       INTEGER    -- QP
 * }
 *
 * Returns total DER size (> 0) written to buf, or negative errno.
 */
int mbedcrypto_pk_encode_rsa_privkey_der(struct mbedcrypto_rsa_ctx *rsa,
		uint8_t *buf, size_t buflen)
{
	uint8_t *p = buf + buflen;
	int ret, len = 0;
	struct mbedcrypto_bignum version;

	if (!rsa || !buf || buflen == 0)
		return -EINVAL;

	/* Write backwards: QP, DQ, DP, Q, P, D, E, N */
	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->QP);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->DQ);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->DP);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->Q);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->P);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->D);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->E);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_bn(&p, buf, &rsa->N);
	if (ret < 0)
		return ret;
	len += ret;

	/* Version = INTEGER(0) */
	mbedcrypto_bn_init(&version);
	ret = mbedcrypto_asn1_write_bn(&p, buf, &version);
	mbedcrypto_bn_cleanup(&version);
	if (ret < 0)
		return ret;
	len += ret;

	/* SEQUENCE header */
	ret = mbedcrypto_asn1_write_len(&p, buf, len);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_tag(&p, buf, MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret < 0)
		return ret;
	len += ret;

	memmove(buf, p, len);
	return len;
}

/* ------------------------------------------------------------------ */
/* EC key DER format support (RFC 5480 / RFC 5915)                    */
/* ------------------------------------------------------------------ */

/* OID: id-ecPublicKey  1.2.840.10045.2.1 */
static const uint8_t oid_ec_pubkey[] = {
	0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};

/* Curve OIDs (DER value bytes only, without tag/length) */
static const uint8_t oid_secp256r1[] = {
	0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07  /* 1.2.840.10045.3.1.7 */
};
static const uint8_t oid_secp384r1[] = {
	0x2B, 0x81, 0x04, 0x00, 0x22  /* 1.3.132.0.34 */
};
static const uint8_t oid_secp521r1[] = {
	0x2B, 0x81, 0x04, 0x00, 0x23  /* 1.3.132.0.35 */
};
static const uint8_t oid_bp256r1[] = {
	0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07  /* 1.3.36.3.3.2.8.1.1.7 */
};
static const uint8_t oid_bp384r1[] = {
	0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B  /* 1.3.36.3.3.2.8.1.1.11 */
};
static const uint8_t oid_bp512r1[] = {
	0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D  /* 1.3.36.3.3.2.8.1.1.13 */
};

struct curve_oid_entry {
	int grp_id;
	const uint8_t *oid;
	size_t oid_len;
};

static const struct curve_oid_entry curve_oid_table[] = {
	{ MBEDCRYPTO_ECP_DP_SECP256R1, oid_secp256r1, sizeof(oid_secp256r1) },
	{ MBEDCRYPTO_ECP_DP_SECP384R1, oid_secp384r1, sizeof(oid_secp384r1) },
	{ MBEDCRYPTO_ECP_DP_SECP521R1, oid_secp521r1, sizeof(oid_secp521r1) },
	{ MBEDCRYPTO_ECP_DP_BP256R1,   oid_bp256r1,   sizeof(oid_bp256r1)   },
	{ MBEDCRYPTO_ECP_DP_BP384R1,   oid_bp384r1,   sizeof(oid_bp384r1)   },
	{ MBEDCRYPTO_ECP_DP_BP512R1,   oid_bp512r1,   sizeof(oid_bp512r1)   },
	{ 0, NULL, 0 }
};

static const struct curve_oid_entry *find_curve_by_grp_id(int grp_id)
{
	const struct curve_oid_entry *e;

	for (e = curve_oid_table; e->oid; e++) {
		if (e->grp_id == grp_id)
			return e;
	}
	return NULL;
}

static int find_grp_id_by_oid(const uint8_t *oid, size_t oid_len)
{
	const struct curve_oid_entry *e;

	for (e = curve_oid_table; e->oid; e++) {
		if (e->oid_len == oid_len &&
		    memcmp(e->oid, oid, oid_len) == 0)
			return e->grp_id;
	}
	return -1;
}

/*
 * Encode EC public key as SubjectPublicKeyInfo DER (RFC 5480).
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm  AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm   OID (id-ecPublicKey),
 *     parameters  OID (namedCurve)
 *   },
 *   subjectPublicKey  BIT STRING (04 || X || Y)
 * }
 *
 * Returns total DER size (> 0) written to buf, or negative errno.
 */
int mbedcrypto_pk_encode_ec_pubkey_der(struct mbedcrypto_ecp_keypair *key,
		uint8_t *buf, size_t buflen)
{
	uint8_t *p = buf + buflen;
	int ret, len = 0, point_len, bitstr_len, algoid_len;
	size_t coord_len = 0;
	const struct curve_oid_entry *curve;

	if (!key || !buf || buflen == 0)
		return -EINVAL;

	curve = find_curve_by_grp_id(key->grp.id);
	if (!curve)
		return -EINVAL;

	coord_len = (key->grp.pbits + 7) / 8;

	/* Write backwards: uncompressed point 04||X||Y */
	if ((size_t)(p - buf) < 1 + 2 * coord_len)
		return -EINVAL;

	p -= coord_len;
	ret = mbedcrypto_bn_to_binary(&key->Q.Y, p, coord_len);
	if (ret != 0)
		return ret;

	p -= coord_len;
	ret = mbedcrypto_bn_to_binary(&key->Q.X, p, coord_len);
	if (ret != 0)
		return ret;

	*--p = 0x04; /* uncompressed */
	point_len = 1 + 2 * coord_len;

	/* BIT STRING: 0x00 unused-bits prefix */
	*--p = 0x00;
	point_len++;

	/* BIT STRING header */
	ret = mbedcrypto_asn1_write_len(&p, buf, point_len);
	if (ret < 0)
		return ret;
	bitstr_len = point_len + ret;

	ret = mbedcrypto_asn1_write_tag(&p, buf, MBEDCRYPTO_ASN1_BIT_STRING);
	if (ret < 0)
		return ret;
	bitstr_len += ret;

	/* AlgorithmIdentifier: curve OID */
	ret = mbedcrypto_asn1_write_oid(&p, buf, curve->oid, curve->oid_len);
	if (ret < 0)
		return ret;
	algoid_len = ret;

	/* AlgorithmIdentifier: id-ecPublicKey OID */
	ret = mbedcrypto_asn1_write_oid(&p, buf, oid_ec_pubkey,
			sizeof(oid_ec_pubkey));
	if (ret < 0)
		return ret;
	algoid_len += ret;

	/* AlgorithmIdentifier SEQUENCE header */
	ret = mbedcrypto_asn1_write_len(&p, buf, algoid_len);
	if (ret < 0)
		return ret;
	algoid_len += ret;

	ret = mbedcrypto_asn1_write_tag(&p, buf, MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret < 0)
		return ret;
	algoid_len += ret;

	len = algoid_len + bitstr_len;

	/* Outer SEQUENCE header */
	ret = mbedcrypto_asn1_write_len(&p, buf, len);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_tag(&p, buf, MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret < 0)
		return ret;
	len += ret;

	memmove(buf, p, len);
	return len;
}

/*
 * Encode EC private key as SEC1 ECPrivateKey DER (RFC 5915).
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER (1),
 *   privateKey     OCTET STRING,
 *   parameters [0] OID (namedCurve)
 * }
 *
 * Returns total DER size (> 0) written to buf, or negative errno.
 */
int mbedcrypto_pk_encode_ec_privkey_der(struct mbedcrypto_ecp_keypair *key,
		uint8_t *buf, size_t buflen)
{
	uint8_t *p = buf + buflen;
	int ret, len = 0, params_len;
	size_t coord_len = 0;
	struct mbedcrypto_bignum version;
	const struct curve_oid_entry *curve;

	if (!key || !buf || buflen == 0)
		return -EINVAL;

	curve = find_curve_by_grp_id(key->grp.id);
	if (!curve)
		return -EINVAL;

	coord_len = (key->grp.pbits + 7) / 8;

	/* [0] EXPLICIT: curve OID */
	ret = mbedcrypto_asn1_write_oid(&p, buf, curve->oid, curve->oid_len);
	if (ret < 0)
		return ret;
	params_len = ret;

	/* [0] EXPLICIT context tag (0xA0) + length */
	ret = mbedcrypto_asn1_write_len(&p, buf, params_len);
	if (ret < 0)
		return ret;
	params_len += ret;

	ret = mbedcrypto_asn1_write_tag(&p, buf, 0xA0);
	if (ret < 0)
		return ret;
	params_len += ret;
	len += params_len;

	/* privateKey OCTET STRING */
	if ((size_t)(p - buf) < coord_len)
		return -EINVAL;
	p -= coord_len;
	ret = mbedcrypto_bn_to_binary(&key->d, p, coord_len);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_asn1_write_len(&p, buf, coord_len);
	if (ret < 0)
		return ret;

	ret = mbedcrypto_asn1_write_tag(&p, buf, MBEDCRYPTO_ASN1_OCTET_STRING);
	if (ret < 0)
		return ret;
	len += coord_len + 1 + 1; /* value + len-byte + tag-byte (for small coords) */
	/* Actually recompute properly */
	len = (buf + buflen) - p;

	/* version INTEGER (1) */
	mbedcrypto_bn_init(&version);
	mbedcrypto_bn_set_word(&version, 1);
	ret = mbedcrypto_asn1_write_bn(&p, buf, &version);
	mbedcrypto_bn_cleanup(&version);
	if (ret < 0)
		return ret;

	len = (buf + buflen) - p;

	/* Outer SEQUENCE header */
	ret = mbedcrypto_asn1_write_len(&p, buf, len);
	if (ret < 0)
		return ret;
	len += ret;

	ret = mbedcrypto_asn1_write_tag(&p, buf, MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret < 0)
		return ret;
	len += ret;

	memmove(buf, p, len);
	return len;
}

/*
 * Decode/Import an EC public key from SubjectPublicKeyInfo DER (RFC 5480).
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm  AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm   OID (id-ecPublicKey),
 *     parameters  OID (namedCurve)
 *   },
 *   subjectPublicKey  BIT STRING (04 || X || Y)
 * }
 *
 * The curve is determined from the embedded OID. No grp_id parameter needed.
 */
int mbedcrypto_pk_decode_ec_pubkey_der(struct mbedcrypto_ecp_keypair *key,
		const uint8_t *buf, size_t buflen)
{
	const uint8_t *p = buf;
	const uint8_t *end = buf + buflen;
	size_t len = 0, oid_len = 0, coord_len = 0;
	const uint8_t *oid_ptr;
	int grp_id = 0, ret = 0;

	if (!key || !buf || buflen == 0)
		return -EINVAL;

	/* Outer SEQUENCE */
	ret = mbedcrypto_asn1_read_tag(&p, end, &len,
			MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret != 0)
		return ret;
	end = p + len;

	/* AlgorithmIdentifier SEQUENCE */
	ret = mbedcrypto_asn1_read_tag(&p, end, &len,
			MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret != 0)
		return ret;

	/* Algorithm OID (id-ecPublicKey) - read and skip */
	ret = mbedcrypto_asn1_read_tag(&p, end, &len,
			MBEDCRYPTO_ASN1_OID);
	if (ret != 0)
		return ret;
	if (len != sizeof(oid_ec_pubkey) ||
	    memcmp(p, oid_ec_pubkey, len) != 0)
		return -EBADMSG; /* not an EC public key */
	p += len;

	/* Curve OID (namedCurve parameter) */
	ret = mbedcrypto_asn1_read_tag(&p, end, &oid_len,
			MBEDCRYPTO_ASN1_OID);
	if (ret != 0)
		return ret;
	oid_ptr = p;
	p += oid_len;

	grp_id = find_grp_id_by_oid(oid_ptr, oid_len);
	if (grp_id < 0)
		return -EBADMSG;

	/* Load curve parameters */
	ret = mbedcrypto_ecp_load_group(&key->grp, grp_id);
	if (ret != 0)
		return ret;

	coord_len = (key->grp.pbits + 7) / 8;

	/* BIT STRING */
	ret = mbedcrypto_asn1_read_tag(&p, end, &len,
			MBEDCRYPTO_ASN1_BIT_STRING);
	if (ret != 0)
		return ret;

	/* Skip unused-bits byte (must be 0x00) */
	if (len < 1 || *p != 0x00)
		return -EBADMSG;
	p++;
	len--;

	/* Expect uncompressed point: 04 || X || Y */
	if (len != 1 + 2 * coord_len || *p != 0x04)
		return -EBADMSG;
	p++; /* skip 0x04 */

	/* Import X */
	ret = mbedcrypto_bn_from_binary(&key->Q.X, p, coord_len);
	if (ret != 0)
		return ret;
	p += coord_len;

	/* Import Y */
	ret = mbedcrypto_bn_from_binary(&key->Q.Y, p, coord_len);
	if (ret != 0)
		return ret;

	/* Set Z = 1 (affine) */
	ret = mbedcrypto_bn_set_word(&key->Q.Z, 1);
	return ret;
}

/*
 * Decode/Import an EC private key from SEC1 ECPrivateKey DER (RFC 5915).
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER (1),
 *   privateKey     OCTET STRING,
 *   parameters [0] OID (namedCurve)
 * }
 *
 * The curve is determined from the embedded OID. No grp_id parameter needed.
 */
int mbedcrypto_pk_decode_ec_privkey_der(struct mbedcrypto_ecp_keypair *key,
		const uint8_t *buf, size_t buflen)
{
	const uint8_t *p = buf;
	const uint8_t *end = buf + buflen;
	const uint8_t *priv_data;
	size_t len = 0, priv_len = 0, oid_len = 0;
	const uint8_t *oid_ptr;
	struct mbedcrypto_bignum version;
	int grp_id = 0, ret = 0;

	if (!key || !buf || buflen == 0)
		return -EINVAL;

	/* Outer SEQUENCE */
	ret = mbedcrypto_asn1_read_tag(&p, end, &len,
			MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret != 0)
		return ret;
	end = p + len;

	/* version INTEGER (must be 1) */
	mbedcrypto_bn_init(&version);
	ret = mbedcrypto_asn1_read_bn(&p, end, &version);
	mbedcrypto_bn_cleanup(&version);
	if (ret != 0)
		return ret;

	/* privateKey OCTET STRING */
	ret = mbedcrypto_asn1_read_tag(&p, end, &priv_len,
			MBEDCRYPTO_ASN1_OCTET_STRING);
	if (ret != 0)
		return ret;
	priv_data = p;
	p += priv_len;

	/* parameters [0] EXPLICIT - context tag 0xA0 */
	ret = mbedcrypto_asn1_read_tag(&p, end, &len, 0xA0);
	if (ret != 0)
		return ret;

	/* Curve OID inside [0] */
	ret = mbedcrypto_asn1_read_tag(&p, end, &oid_len,
			MBEDCRYPTO_ASN1_OID);
	if (ret != 0)
		return ret;
	oid_ptr = p;

	grp_id = find_grp_id_by_oid(oid_ptr, oid_len);
	if (grp_id < 0)
		return -EBADMSG;

	/* Load curve parameters */
	ret = mbedcrypto_ecp_load_group(&key->grp, grp_id);
	if (ret != 0)
		return ret;

	/* Import private scalar d */
	ret = mbedcrypto_bn_from_binary(&key->d, priv_data, priv_len);
	return ret;
}

/* ------------------------------------------------------------------ */
/* File-based key loading helpers                                     */
/* ------------------------------------------------------------------ */

/*
 * Read an entire file into a malloc'd buffer.
 * On success, *buf receives the pointer and *buflen the size.
 */
static int mbedcrypto_pk_read_file(const char *path, uint8_t **buf, size_t *buflen)
{
	FILE *f;
	int ret;
	struct stat st;
	uint8_t *p = NULL;

	if (stat(path, &st) != 0) {
		ret = -errno;
		return ret ? ret : -EIO;
	}

	p = malloc(st.st_size);
	if (!p)
		return -ENOMEM;

	f = fopen(path, "rb");
	if (!f) {
		ret = -errno;
		free(p);
		return ret ? ret : -EIO;
	}

	if (fread(p, 1, st.st_size, f) != (size_t)st.st_size) {
		ret = -errno;
		fclose(f);
		free(p);
		return ret ? ret : -EIO;
	}

	fclose(f);
	*buf = p;
	*buflen = st.st_size;
	return 0;
}

int mbedcrypto_pk_decode_rsa_pubkey_file(struct mbedcrypto_rsa_ctx *rsa,
		const char *path)
{
	uint8_t *buf = NULL;
	size_t len = 0;
	int ret = 0;

	ret = mbedcrypto_pk_read_file(path, &buf, &len);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_pk_decode_rsa_pubkey_der(rsa, buf, len);
	free(buf);
	return ret;
}

int mbedcrypto_pk_decode_rsa_privkey_file(struct mbedcrypto_rsa_ctx *rsa,
		const char *path)
{
	uint8_t *buf = NULL;
	size_t len = 0;
	int ret = 0;

	ret = mbedcrypto_pk_read_file(path, &buf, &len);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_pk_decode_rsa_privkey_der(rsa, buf, len);
	free(buf);
	return ret;
}

int mbedcrypto_pk_decode_ec_pubkey_file(struct mbedcrypto_ecp_keypair *key,
		const char *path)
{
	uint8_t *buf = NULL;
	size_t len = 0;
	int ret = 0;

	ret = mbedcrypto_pk_read_file(path, &buf, &len);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_pk_decode_ec_pubkey_der(key, buf, len);
	free(buf);
	return ret;
}

int mbedcrypto_pk_decode_ec_privkey_file(struct mbedcrypto_ecp_keypair *key,
		const char *path)
{
	uint8_t *buf = NULL;
	size_t len = 0;
	int ret = 0;

	ret = mbedcrypto_pk_read_file(path, &buf, &len);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_pk_decode_ec_privkey_der(key, buf, len);
	free(buf);
	return ret;
}

int mbedcrypto_pk_decode_dh_params_file(struct mbedcrypto_dh_ctx *ctx,
		const char *path)
{
	uint8_t *buf = NULL;
	size_t len = 0;
	int ret = 0;

	ret = mbedcrypto_pk_read_file(path, &buf, &len);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_pk_decode_dh_params_der(ctx, buf, len);
	free(buf);
	return ret;
}

/* ------------------------------------------------------------------ */
/* File-based key writing helpers                                     */
/* ------------------------------------------------------------------ */

static int mbedcrypto_pk_write_file(const char *path,
		const uint8_t *buf, size_t len)
{
	int ret;
	FILE *f;

	f = fopen(path, "wb");
	if (!f) {
		ret = -errno;
		return ret ? ret : -EIO;
	}

	if (fwrite(buf, 1, len, f) != len) {
		ret = -errno;
		fclose(f);
		return ret ? ret : -EIO;
	}

	fclose(f);
	return 0;
}

int mbedcrypto_pk_encode_rsa_pubkey_file(struct mbedcrypto_rsa_ctx *rsa,
		const char *path)
{
	uint8_t buf[1024];
	int ret = 0;

	ret = mbedcrypto_pk_encode_rsa_pubkey_der(rsa, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	return mbedcrypto_pk_write_file(path, buf, ret);
}

int mbedcrypto_pk_encode_rsa_privkey_file(struct mbedcrypto_rsa_ctx *rsa,
		const char *path)
{
	size_t bufsz = mbedcrypto_rsa_len(rsa) * 8;
	uint8_t *buf = NULL;
	int ret = 0;

	buf = malloc(bufsz);
	if (!buf)
		return -ENOMEM;

	ret = mbedcrypto_pk_encode_rsa_privkey_der(rsa, buf, bufsz);
	if (ret >= 0)
		ret = mbedcrypto_pk_write_file(path, buf, ret);

	free(buf);
	return ret;
}

int mbedcrypto_pk_encode_ec_pubkey_file(struct mbedcrypto_ecp_keypair *key,
		const char *path)
{
	uint8_t buf[256]; /* SPKI DER: max ~160 bytes for BP-512 */
	int ret = 0;

	ret = mbedcrypto_pk_encode_ec_pubkey_der(key, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	return mbedcrypto_pk_write_file(path, buf, ret);
}

int mbedcrypto_pk_encode_ec_privkey_file(struct mbedcrypto_ecp_keypair *key,
		const char *path)
{
	uint8_t buf[128]; /* SEC1 DER: max ~100 bytes for BP-512 */
	int ret = 0;

	ret = mbedcrypto_pk_encode_ec_privkey_der(key, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	return mbedcrypto_pk_write_file(path, buf, ret);
}
