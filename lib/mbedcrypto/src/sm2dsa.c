// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SM2 Digital Signature Algorithm (GB/T 32918.2-2016)
 */

#include <string.h>

#include <mbedcrypto/sm2dsa.h>
#include <mbedcrypto/asn1.h>

/* ---------------------------------------------------------------- */
/*  Context lifecycle                                               */
/* ---------------------------------------------------------------- */

void mbedcrypto_sm2dsa_init(struct mbedcrypto_sm2dsa_ctx *ctx)
{
	mbedcrypto_ecp_group_init(&ctx->grp);
	mbedcrypto_bn_init(&ctx->d);
	mbedcrypto_ecp_point_init(&ctx->Q);
}

void mbedcrypto_sm2dsa_cleanup(struct mbedcrypto_sm2dsa_ctx *ctx)
{
	mbedcrypto_ecp_group_cleanup(&ctx->grp);
	mbedcrypto_bn_cleanup(&ctx->d);
	mbedcrypto_ecp_point_cleanup(&ctx->Q);
}

int mbedcrypto_sm2dsa_load_group(struct mbedcrypto_sm2dsa_ctx *ctx)
{
	return mbedcrypto_ecp_load_group(&ctx->grp, MBEDCRYPTO_ECP_DP_SM2);
}

/* ---------------------------------------------------------------- */
/*  Z value computation                                             */
/* ---------------------------------------------------------------- */

/*
 * Compute Z_A = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
 *
 * ENTL = 2-byte big-endian bit length of ID
 */
int mbedcrypto_sm2_compute_z(const struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *id, size_t idlen, uint8_t z[32])
{
	struct mbedcrypto_sm3_ctx sm3;
	uint8_t entl[2];
	uint8_t buf[32];
	size_t bitlen = 0;
	int ret = 0;

	if (idlen > 8191) /* ENTL is 16-bit, max 65535 bits */
		return -EINVAL;

	bitlen = idlen * 8;
	entl[0] = bitlen >> 8 & 0xff;
	entl[1] = bitlen & 0xff;

	ret = mbedcrypto_sm3_init(&sm3);
	if (ret != 0)
		return ret;

	mbedcrypto_sm3_update(&sm3, entl, 2);
	mbedcrypto_sm3_update(&sm3, id, idlen);

	/*
	 * a: grp->A may be stored as -3 (signed). Convert to
	 * the modular representative (P + A) for hashing.
	 */
	if (ctx->grp.A.neg) {
		struct mbedcrypto_bignum a_mod;

		mbedcrypto_bn_init(&a_mod);
		ret = mbedcrypto_bn_add(&a_mod, &ctx->grp.P, &ctx->grp.A);
		if (ret != 0) {
			mbedcrypto_bn_cleanup(&a_mod);
			mbedcrypto_sm3_cleanup(&sm3);
			return ret;
		}
		mbedcrypto_bn_to_binary(&a_mod, buf, 32);
		mbedcrypto_bn_cleanup(&a_mod);
	} else
		mbedcrypto_bn_to_binary(&ctx->grp.A, buf, 32);

	mbedcrypto_sm3_update(&sm3, buf, 32);

	/* b */
	mbedcrypto_bn_to_binary(&ctx->grp.B, buf, 32);
	mbedcrypto_sm3_update(&sm3, buf, 32);

	/* xG */
	mbedcrypto_bn_to_binary(&ctx->grp.G.X, buf, 32);
	mbedcrypto_sm3_update(&sm3, buf, 32);

	/* yG */
	mbedcrypto_bn_to_binary(&ctx->grp.G.Y, buf, 32);
	mbedcrypto_sm3_update(&sm3, buf, 32);

	/* xA */
	mbedcrypto_bn_to_binary(&ctx->Q.X, buf, 32);
	mbedcrypto_sm3_update(&sm3, buf, 32);

	/* yA */
	mbedcrypto_bn_to_binary(&ctx->Q.Y, buf, 32);
	mbedcrypto_sm3_update(&sm3, buf, 32);

	ret = mbedcrypto_sm3_final(&sm3, z);
	mbedcrypto_sm3_cleanup(&sm3);
	return ret;
}

/* ---------------------------------------------------------------- */
/*  SM2 Sign                                                        */
/* ---------------------------------------------------------------- */

/*
 * SM2 signature algorithm:
 *   1. Generate random k in [1, n-1]
 *   2. Compute (x1, y1) = k * G
 *   3. r = (e + x1) mod n, reject if r == 0 or r + k == n
 *   4. s = ((1 + d)^(-1) * (k - r * d)) mod n, reject if s == 0
 *   5. Output raw (r, s)
 */
int mbedcrypto_sm2dsa_sign(struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	struct mbedcrypto_bignum r, s, k, tmp;
	struct mbedcrypto_ecp_point kG;
	struct mbedcrypto_bignum e_bn;
	int ret = 0;

	mbedcrypto_bn_init(&r);
	mbedcrypto_bn_init(&s);
	mbedcrypto_bn_init(&k);
	mbedcrypto_bn_init(&tmp);
	mbedcrypto_bn_init(&e_bn);
	mbedcrypto_ecp_point_init(&kG);

	if ((ret = mbedcrypto_bn_from_binary(&e_bn, e, elen)) != 0)
		goto cleanup;

retry:
	/* Step 1: random k in [1, n-1] */
	if ((ret = mbedcrypto_bn_random(&k, 32, f_rng, p_rng)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&k, &k, &ctx->grp.N)) != 0)
		goto cleanup;
	if (mbedcrypto_bn_cmp_word(&k, 0) == 0)
		goto retry;

	/* Step 2: (x1, y1) = k * G */
	if ((ret = mbedcrypto_ecp_scalar_mul(&ctx->grp, &kG, &k, &ctx->grp.G, f_rng, p_rng)) != 0)
		goto cleanup;

	/* Step 3: r = (e + x1) mod n */
	if ((ret = mbedcrypto_bn_add(&r, &e_bn, &kG.X)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&r, &r, &ctx->grp.N)) != 0)
		goto cleanup;

	/* Check r == 0 */
	if (mbedcrypto_bn_cmp_word(&r, 0) == 0)
		goto retry;

	/* Check r + k == n */
	if ((ret = mbedcrypto_bn_add(&tmp, &r, &k)) != 0)
		goto cleanup;
	if (mbedcrypto_bn_cmp(&tmp, &ctx->grp.N) == 0)
		goto retry;

	/* Step 4: s = ((1 + d)^(-1) * (k - r * d)) mod n */
	/* tmp = 1 + d */
	if ((ret = mbedcrypto_bn_add_word(&tmp, &ctx->d, 1)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&tmp, &tmp, &ctx->grp.N)) != 0)
		goto cleanup;

	/* tmp = (1 + d)^(-1) mod n */
	if ((ret = mbedcrypto_bn_modinv(&tmp, &tmp, &ctx->grp.N)) != 0)
		goto cleanup;

	/* s = r * d */
	if ((ret = mbedcrypto_bn_mul(&s, &r, &ctx->d)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&s, &s, &ctx->grp.N)) != 0)
		goto cleanup;

	/* s = k - r * d (mod n) */
	if ((ret = mbedcrypto_bn_sub(&s, &k, &s)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&s, &s, &ctx->grp.N)) != 0)
		goto cleanup;

	/* s = (1+d)^(-1) * (k - r*d) mod n */
	if ((ret = mbedcrypto_bn_mul(&s, &tmp, &s)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&s, &s, &ctx->grp.N)) != 0)
		goto cleanup;

	if (mbedcrypto_bn_cmp_word(&s, 0) == 0)
		goto retry;

	/* Step 5: raw (r, s) - each 32 bytes big-endian */
	if (sig_size < 64) {
		ret = -ERANGE;
		goto cleanup;
	}

	ret = mbedcrypto_bn_to_binary(&r, sig, 32);
	if (ret != 0)
		goto cleanup;
	ret = mbedcrypto_bn_to_binary(&s, sig + 32, 32);
	if (ret != 0)
		goto cleanup;

	*slen = 64;
	ret = 0;

cleanup:
	mbedcrypto_bn_cleanup(&r);
	mbedcrypto_bn_cleanup(&s);
	mbedcrypto_bn_cleanup(&k);
	mbedcrypto_bn_cleanup(&tmp);
	mbedcrypto_bn_cleanup(&e_bn);
	mbedcrypto_ecp_point_cleanup(&kG);
	return ret;
}

/* ---------------------------------------------------------------- */
/*  SM2 Verify                                                      */
/* ---------------------------------------------------------------- */

/*
 * SM2 verification:
 *   1. Parse raw (r, s)
 *   2. t = (r + s) mod n, reject if t == 0
 *   3. Compute (x1, y1) = s * G + t * Q
 *   4. R = (e + x1) mod n
 *   5. Accept if R == r
 */
int mbedcrypto_sm2dsa_verify(struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		const uint8_t *sig, size_t slen)
{
	struct mbedcrypto_bignum r, s, t, e_bn, R;
	struct mbedcrypto_ecp_point pt;
	int ret = 0;

	if (slen != 64)
		return -EBADMSG;

	mbedcrypto_bn_init(&r);
	mbedcrypto_bn_init(&s);
	mbedcrypto_bn_init(&t);
	mbedcrypto_bn_init(&e_bn);
	mbedcrypto_bn_init(&R);
	mbedcrypto_ecp_point_init(&pt);

	/* Parse raw (r, s) - each 32 bytes big-endian */
	if ((ret = mbedcrypto_bn_from_binary(&r, sig, 32)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_from_binary(&s, sig + 32, 32)) != 0)
		goto cleanup;

	if ((ret = mbedcrypto_bn_from_binary(&e_bn, e, elen)) != 0)
		goto cleanup;

	/* Check r, s in [1, n-1] */
	if (mbedcrypto_bn_cmp_word(&r, 1) < 0 ||
	    mbedcrypto_bn_cmp(&r, &ctx->grp.N) >= 0 ||
	    mbedcrypto_bn_cmp_word(&s, 1) < 0 ||
	    mbedcrypto_bn_cmp(&s, &ctx->grp.N) >= 0) {
		ret = -EBADMSG;
		goto cleanup;
	}

	/* t = (r + s) mod n */
	if ((ret = mbedcrypto_bn_add(&t, &r, &s)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&t, &t, &ctx->grp.N)) != 0)
		goto cleanup;

	if (mbedcrypto_bn_cmp_word(&t, 0) == 0) {
		ret = -EBADMSG;
		goto cleanup;
	}

	/* (x1, y1) = s*G + t*Q */
	if ((ret = mbedcrypto_ecp_dual_scalar_mul(&ctx->grp, &pt, &s, &ctx->grp.G, &t, &ctx->Q)) != 0)
		goto cleanup;

	/* R = (e + x1) mod n */
	if ((ret = mbedcrypto_bn_add(&R, &e_bn, &pt.X)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&R, &R, &ctx->grp.N)) != 0)
		goto cleanup;

	/* Accept if R == r */
	if (mbedcrypto_bn_cmp(&R, &r) != 0)
		ret = -EBADMSG;
	else
		ret = 0;

cleanup:
	mbedcrypto_bn_cleanup(&r);
	mbedcrypto_bn_cleanup(&s);
	mbedcrypto_bn_cleanup(&t);
	mbedcrypto_bn_cleanup(&e_bn);
	mbedcrypto_bn_cleanup(&R);
	mbedcrypto_ecp_point_cleanup(&pt);
	return ret;
}

/* ---------------------------------------------------------------- */
/*  DER wrappers (reuse raw sign/verify)                            */
/* ---------------------------------------------------------------- */

int mbedcrypto_sm2dsa_sign_der(struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	struct mbedcrypto_bignum r, s;
	uint8_t raw[64];
	size_t raw_len = 0;
	uint8_t *p = NULL;
	int ret = 0;
	int len = 0;

	ret = mbedcrypto_sm2dsa_sign(ctx, e, elen,
			raw, sizeof(raw), &raw_len, f_rng, p_rng);
	if (ret != 0)
		return ret;

	mbedcrypto_bn_init(&r);
	mbedcrypto_bn_init(&s);

	if ((ret = mbedcrypto_bn_from_binary(&r, raw, 32)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_from_binary(&s,
				raw + 32, 32)) != 0)
		goto cleanup;

	p = sig + sig_size;

	len = mbedcrypto_asn1_write_bn(&p, sig, &s);
	if (len < 0) { ret = len; goto cleanup; }

	ret = mbedcrypto_asn1_write_bn(&p, sig, &r);
	if (ret < 0)
		goto cleanup;
	len += ret;

	ret = mbedcrypto_asn1_write_len(&p, sig, len);
	if (ret < 0)
		goto cleanup;
	len += ret;

	ret = mbedcrypto_asn1_write_tag(&p, sig,
			MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret < 0)
		goto cleanup;
	len += ret;

	memmove(sig, p, len);
	*slen = len;
	ret = 0;

cleanup:
	mbedcrypto_bn_cleanup(&r);
	mbedcrypto_bn_cleanup(&s);
	return ret;
}

int mbedcrypto_sm2dsa_verify_der(struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		const uint8_t *sig, size_t slen)
{
	struct mbedcrypto_bignum r, s;
	const uint8_t *p = sig;
	const uint8_t *end = sig + slen;
	size_t seq_len = 0;
	uint8_t raw[64];
	int ret = 0;

	ret = mbedcrypto_asn1_read_tag(&p, end, &seq_len,
			MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret != 0)
		return -EBADMSG;

	end = p + seq_len;

	mbedcrypto_bn_init(&r);
	mbedcrypto_bn_init(&s);

	if ((ret = mbedcrypto_asn1_read_bn(&p, end, &r)) != 0)
		goto fail;
	if ((ret = mbedcrypto_asn1_read_bn(&p, end, &s)) != 0)
		goto fail;

	if ((ret = mbedcrypto_bn_to_binary(&r, raw, 32)) != 0)
		goto fail;
	if ((ret = mbedcrypto_bn_to_binary(&s,
				raw + 32, 32)) != 0)
		goto fail;

	mbedcrypto_bn_cleanup(&r);
	mbedcrypto_bn_cleanup(&s);
	return mbedcrypto_sm2dsa_verify(ctx, e, elen, raw, 64);

fail:
	mbedcrypto_bn_cleanup(&r);
	mbedcrypto_bn_cleanup(&s);
	return -EBADMSG;
}
