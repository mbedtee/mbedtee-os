// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Elliptic Curve Digital Signature Algorithm (ECDSA)
 *
 * Sign: pick random k in [1,n-1], compute R = k*G, r = R.x mod n,
 *       s = k^-1 * (hash + r*d) mod n.
 * Verify: w = s^-1, u1 = hash*w, u2 = r*w,
 *         R = u1*G + u2*Q, check R.x == r (mod n).
 *
 * Signatures are raw: r (n_bytes) || s (n_bytes), big-endian, zero-padded.
 */

#include <string.h>

#include <mbedcrypto/ecdsa.h>
#include <mbedcrypto/asn1.h>
#include <mbedcrypto/types.h>

/* ------------------------------------------------------------------ */
/*  Context lifecycle                                                  */
/* ------------------------------------------------------------------ */

void mbedcrypto_ecdsa_init(struct mbedcrypto_ecdsa_ctx *ctx)
{
	mbedcrypto_ecp_group_init(&ctx->grp);
	mbedcrypto_bn_init(&ctx->d);
	mbedcrypto_ecp_point_init(&ctx->Q);
}

void mbedcrypto_ecdsa_cleanup(struct mbedcrypto_ecdsa_ctx *ctx)
{
	mbedcrypto_ecp_group_cleanup(&ctx->grp);
	mbedcrypto_bn_cleanup(&ctx->d);
	mbedcrypto_ecp_point_cleanup(&ctx->Q);
}

/*
 * Truncate hash to the bit-length of the group order N.
 * Reads min(hlen, n_bytes) bytes, then right-shifts if hash
 * is longer than N in bits.
 */
static int hash_to_scalar(struct mbedcrypto_bignum *e,
		const struct mbedcrypto_ecp_group *grp,
		const uint8_t *hash, size_t hlen)
{
	int ret = 0;
	size_t n_bytes = (grp->nbits + 7) / 8;

	if ((ret = mbedcrypto_bn_from_binary(e, hash, (hlen < n_bytes) ? hlen : n_bytes)) != 0)
		return ret;

	if (hlen * 8 > grp->nbits) {
		if ((ret = mbedcrypto_bn_rshift(e, hlen * 8 - grp->nbits)) != 0)
			return ret;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Internal: compute raw (r,s)                                        */
/* ------------------------------------------------------------------ */

/*
 * Sign the hash. Returns r and s as bignums.
 */
static int ecdsa_sign_raw(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_bignum *r, struct mbedcrypto_bignum *s,
		const struct mbedcrypto_bignum *d,
		const uint8_t *hash, size_t hlen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret, count = 0;
	struct mbedcrypto_bignum k, e, kinv, t;
	struct mbedcrypto_ecp_point R;
	size_t n_bytes = (grp->nbits + 7) / 8;

	mbedcrypto_bn_init(&k);
	mbedcrypto_bn_init(&e);
	mbedcrypto_bn_init(&kinv);
	mbedcrypto_bn_init(&t);
	mbedcrypto_ecp_point_init(&R);

	if ((ret = hash_to_scalar(&e, grp, hash, hlen)) != 0)
		goto cleanup;

	do {
		/* Pick random k in [1, N-1] */
		do {
			if ((ret = mbedcrypto_bn_random(&k, n_bytes, f_rng, p_rng)) != 0)
				goto cleanup;

			if (n_bytes * 8 > grp->nbits) {
				if ((ret = mbedcrypto_bn_rshift(&k, n_bytes * 8 - grp->nbits)) != 0)
					goto cleanup;
			}

			if (count++ > 30) { ret = -EAGAIN; goto cleanup; }
		} while (mbedcrypto_bn_cmp(&k, &grp->N) >= 0 ||
			 mbedcrypto_bn_cmp_word(&k, 1) < 0);

		/* R = k * G */
		if ((ret = mbedcrypto_ecp_scalar_mul(grp, &R, &k, &grp->G, f_rng, p_rng)) != 0)
			goto cleanup;

		/* r = R.x mod N */
		if ((ret = mbedcrypto_bn_mod(r, &R.X, &grp->N)) != 0)
			goto cleanup;

		if (mbedcrypto_bn_cmp_word(r, 0) == 0)
			continue;

		/* s = k^(-1) * (e + r*d) mod N */
		if ((ret = mbedcrypto_bn_modinv(&kinv, &k, &grp->N)) != 0)
			goto cleanup;

		if ((ret = mbedcrypto_bn_mul(&t, r, d)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_add(&t, &t, &e)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_mul(s, &kinv, &t)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_mod(s, s, &grp->N)) != 0)
			goto cleanup;

	} while (mbedcrypto_bn_cmp_word(s, 0) == 0);

cleanup:
	mbedcrypto_bn_cleanup(&k);
	mbedcrypto_bn_cleanup(&e);
	mbedcrypto_bn_cleanup(&kinv);
	mbedcrypto_bn_cleanup(&t);
	mbedcrypto_ecp_point_cleanup(&R);
	return ret;
}

/*
 * Verify the hash against (r, s). Returns 0 if valid.
 */
static int ecdsa_verify_raw(struct mbedcrypto_ecp_group *grp,
		const uint8_t *hash, size_t hlen,
		const struct mbedcrypto_ecp_point *Q,
		const struct mbedcrypto_bignum *r,
		const struct mbedcrypto_bignum *s)
{
	int ret = 0;
	struct mbedcrypto_bignum e, w, u1, u2;
	struct mbedcrypto_ecp_point R;

	/* Check r, s in [1, N-1] */
	if (mbedcrypto_bn_cmp_word(r, 1) < 0 ||
	    mbedcrypto_bn_cmp(r, &grp->N) >= 0 ||
	    mbedcrypto_bn_cmp_word(s, 1) < 0 ||
	    mbedcrypto_bn_cmp(s, &grp->N) >= 0)
		return -EBADMSG;

	mbedcrypto_bn_init(&e);
	mbedcrypto_bn_init(&w);
	mbedcrypto_bn_init(&u1);
	mbedcrypto_bn_init(&u2);
	mbedcrypto_ecp_point_init(&R);

	if ((ret = hash_to_scalar(&e, grp, hash, hlen)) != 0)
		goto cleanup;

	/* w = s^-1 mod N */
	if ((ret = mbedcrypto_bn_modinv(&w, s, &grp->N)) != 0)
		goto cleanup;

	/* u1 = e * w mod N */
	if ((ret = mbedcrypto_bn_mul(&u1, &e, &w)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&u1, &u1, &grp->N)) != 0)
		goto cleanup;

	/* u2 = r * w mod N */
	if ((ret = mbedcrypto_bn_mul(&u2, r, &w)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&u2, &u2, &grp->N)) != 0)
		goto cleanup;

	/* R = u1*G + u2*Q */
	if ((ret = mbedcrypto_ecp_dual_scalar_mul(grp, &R, &u1, &grp->G, &u2, Q)) != 0)
		goto cleanup;

	if (mbedcrypto_ecp_is_infinity(&R)) {
		ret = -EBADMSG;
		goto cleanup;
	}

	/* Check R.x mod N == r */
	if ((ret = mbedcrypto_bn_mod(&R.X, &R.X, &grp->N)) != 0)
		goto cleanup;

	if (mbedcrypto_bn_cmp(&R.X, r) != 0)
		ret = -EBADMSG;
	else
		ret = 0;

cleanup:
	mbedcrypto_bn_cleanup(&e);
	mbedcrypto_bn_cleanup(&w);
	mbedcrypto_bn_cleanup(&u1);
	mbedcrypto_bn_cleanup(&u2);
	mbedcrypto_ecp_point_cleanup(&R);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

int mbedcrypto_ecdsa_sign(struct mbedcrypto_ecdsa_ctx *ctx,
		int hash_id,
		const uint8_t *digest, size_t dlen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;
	struct mbedcrypto_bignum r, s;
	size_t n_bytes = (ctx->grp.nbits + 7) / 8;

	if (sig_size < 2 * n_bytes)
		return -ERANGE;

	mbedcrypto_bn_init(&r);
	mbedcrypto_bn_init(&s);

	ret = ecdsa_sign_raw(&ctx->grp, &r, &s, &ctx->d,
			digest, dlen, f_rng, p_rng);
	if (ret != 0)
		goto cleanup;

	/* Raw signature: r (n_bytes) || s (n_bytes) */
	ret = mbedcrypto_bn_to_binary(&r, sig, n_bytes);
	if (ret == 0)
		ret = mbedcrypto_bn_to_binary(&s, sig + n_bytes, n_bytes);
	if (ret == 0)
		*slen = 2 * n_bytes;

cleanup:
	mbedcrypto_bn_cleanup(&r);
	mbedcrypto_bn_cleanup(&s);
	return ret;
}

int mbedcrypto_ecdsa_verify(struct mbedcrypto_ecdsa_ctx *ctx,
		const uint8_t *digest, size_t dlen,
		const uint8_t *sig, size_t slen)
{
	int ret = 0;
	struct mbedcrypto_bignum r, s;
	size_t n_bytes = (ctx->grp.nbits + 7) / 8;

	if (slen != 2 * n_bytes)
		return -EBADMSG;

	mbedcrypto_bn_init(&r);
	mbedcrypto_bn_init(&s);

	if ((ret = mbedcrypto_bn_from_binary(&r, sig, n_bytes)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_from_binary(&s, sig + n_bytes, n_bytes)) != 0)
		goto cleanup;

	ret = ecdsa_verify_raw(&ctx->grp, digest, dlen, &ctx->Q, &r, &s);

cleanup:
	mbedcrypto_bn_cleanup(&r);
	mbedcrypto_bn_cleanup(&s);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  DER wrappers (reuse raw sign/verify)                               */
/* ------------------------------------------------------------------ */

int mbedcrypto_ecdsa_sign_der(struct mbedcrypto_ecdsa_ctx *ctx,
		int hash_id,
		const uint8_t *digest, size_t dlen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	struct mbedcrypto_bignum r, s;
	uint8_t raw[132];
	size_t raw_len = 0;
	size_t n_bytes = 0;
	uint8_t *p = NULL;
	int ret = 0;
	int len = 0;

	ret = mbedcrypto_ecdsa_sign(ctx, hash_id, digest, dlen,
			raw, sizeof(raw), &raw_len, f_rng, p_rng);
	if (ret != 0)
		return ret;

	n_bytes = raw_len / 2;
	mbedcrypto_bn_init(&r);
	mbedcrypto_bn_init(&s);

	if ((ret = mbedcrypto_bn_from_binary(&r, raw, n_bytes)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_from_binary(&s,
				raw + n_bytes, n_bytes)) != 0)
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

int mbedcrypto_ecdsa_verify_der(struct mbedcrypto_ecdsa_ctx *ctx,
		const uint8_t *digest, size_t dlen,
		const uint8_t *sig, size_t slen)
{
	struct mbedcrypto_bignum r, s;
	const uint8_t *p = sig;
	const uint8_t *end = sig + slen;
	size_t seq_len = 0, n_bytes = 0;
	uint8_t raw[132];
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

	n_bytes = (ctx->grp.nbits + 7) / 8;

	if ((ret = mbedcrypto_bn_to_binary(&r, raw, n_bytes)) != 0)
		goto fail;
	if ((ret = mbedcrypto_bn_to_binary(&s,
				raw + n_bytes, n_bytes)) != 0)
		goto fail;

	mbedcrypto_bn_cleanup(&r);
	mbedcrypto_bn_cleanup(&s);
	return mbedcrypto_ecdsa_verify(ctx, digest, dlen,
			raw, 2 * n_bytes);

fail:
	mbedcrypto_bn_cleanup(&r);
	mbedcrypto_bn_cleanup(&s);
	return -EBADMSG;
}
