// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * DSA digital signatures (FIPS 186)
 *
 * Supports key sizes: 512-1024/160, 2048/256, 3072/256.
 * Signing uses blinding for side-channel resistance.
 */

#include <string.h>

#include <mbedcrypto/dsa.h>
#include <mbedcrypto/asn1.h>

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

void mbedcrypto_dsa_init(struct mbedcrypto_dsa_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

void mbedcrypto_dsa_cleanup(struct mbedcrypto_dsa_ctx *ctx)
{
	if (!ctx)
		return;
	mbedcrypto_bn_cleanup(&ctx->X);
	mbedcrypto_bn_cleanup(&ctx->Y);
	mbedcrypto_bn_cleanup(&ctx->G);
	mbedcrypto_bn_cleanup(&ctx->Q);
	mbedcrypto_bn_cleanup(&ctx->P);
}

/* ------------------------------------------------------------------ */
/*  Key-size validation (FIPS 186)                                     */
/* ------------------------------------------------------------------ */

static int dsa_check_pq(int modulus, int divisor)
{
	switch (modulus) {
	case 2048:
		if (divisor == 224 || divisor == 256)
			return 0;
		break;
	case 3072:
		if (divisor == 256)
			return 0;
		break;
	default:
		if (modulus >= 512 && modulus <= 1024 &&
		    !(modulus % 64) && (divisor == 160))
			return 0;
		break;
	}
	return -1;
}

static int dsa_check_params(const struct mbedcrypto_dsa_ctx *ctx)
{
	int modulus = 0, divisor = 0;

	modulus = mbedcrypto_bn_bit_count(&ctx->P);
	divisor = mbedcrypto_bn_bit_count(&ctx->Q);

	if (dsa_check_pq(modulus, divisor) != 0)
		return -EINVAL;

	if (mbedcrypto_bn_test_bit(&ctx->Q, 0) == 0 ||
	    mbedcrypto_bn_test_bit(&ctx->P, 0) == 0 ||
	    mbedcrypto_bn_bit_count(&ctx->G) < 2 ||
	    mbedcrypto_bn_cmp(&ctx->G, &ctx->P) >= 0)
		return -EINVAL;

	return 0;
}

int mbedcrypto_dsa_validate_pubkey(const struct mbedcrypto_dsa_ctx *ctx)
{
	int ret = 0;

	if (!ctx)
		return -EINVAL;

	if ((ret = dsa_check_params(ctx)) != 0)
		return ret;

	if (mbedcrypto_bn_bit_count(&ctx->Y) >
	    mbedcrypto_bn_bit_count(&ctx->P))
		return -EINVAL;

	return 0;
}

int mbedcrypto_dsa_validate_privkey(const struct mbedcrypto_dsa_ctx *ctx)
{
	int ret = 0;

	if (!ctx)
		return -EINVAL;

	if ((ret = dsa_check_params(ctx)) != 0)
		return ret;

	if (mbedcrypto_bn_bit_count(&ctx->X) >
	    mbedcrypto_bn_bit_count(&ctx->Q))
		return -EINVAL;

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Parameter generation                                               */
/* ------------------------------------------------------------------ */

int mbedcrypto_dsa_gen_params(struct mbedcrypto_dsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		unsigned int nbits)
{
	int count = 0, q_len = 0, t_len = 0;
	int ret = 0;
	struct mbedcrypto_bignum T, H, Q2;

	if (!ctx || !f_rng)
		return -EINVAL;

	if ((nbits == 3072) || (nbits == 2048))
		q_len = 32; /* 256-bit Q */
	else if (nbits >= 512 && nbits <= 1024 && !(nbits % 64))
		q_len = 20; /* 160-bit Q */
	else
		return -EINVAL;

	mbedcrypto_bn_init(&ctx->P);
	mbedcrypto_bn_init(&ctx->Q);
	mbedcrypto_bn_init(&ctx->G);
	mbedcrypto_bn_init(&T);
	mbedcrypto_bn_init(&H);
	mbedcrypto_bn_init(&Q2);

	t_len = (nbits >> 3) - q_len;

	/* Generate prime Q */
	ret = mbedcrypto_bn_gen_prime(&ctx->Q, q_len << 3,
			0, f_rng, p_rng);
	if (ret != 0)
		goto cleanup;

	/*
	 * Find P = T * Q + 1 where P is prime with bitlen(P) == nbits.
	 * T = random with MSB set, then adjusted upward.
	 */
	do {
		ret = mbedcrypto_bn_random(&T, t_len,
				f_rng, p_rng);
		if (ret != 0)
			goto cleanup;
		/* Set top bits so T * Q is close to nbits */
		ret = mbedcrypto_bn_assign_bit(&T,
				(t_len << 3) - 1, 1);
		if (ret != 0)
			goto cleanup;
		ret = mbedcrypto_bn_assign_bit(&T,
				(t_len << 3) - 2, 1);
		if (ret != 0)
			goto cleanup;

		if ((ret = mbedcrypto_bn_add(&Q2, &ctx->Q, &ctx->Q)) != 0)
			goto cleanup;

		/* Make T even, then compute P = T*Q */
		do {
			if ((ret = mbedcrypto_bn_add(&T, &T, &ctx->Q)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_assign_bit(&T, 0, 0)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_mul(&ctx->P, &T, &ctx->Q)) != 0)
				goto cleanup;
		} while (mbedcrypto_bn_bit_count(&ctx->P) < nbits);

		/* P = T*Q + 1, so Q divides (P - 1) */
		if ((ret = mbedcrypto_bn_add_word(&ctx->P, &ctx->P, 1)) != 0)
			goto cleanup;

		/* Search for prime P by stepping P += 2*Q */
		count = 0;
		do {
			count += 2;
			if ((ret = mbedcrypto_bn_add(&ctx->P, &ctx->P, &Q2)) != 0)
				goto cleanup;
			if (mbedcrypto_bn_bit_count(&ctx->P) > nbits)
				break;
		} while (mbedcrypto_bn_test_prime(&ctx->P, 6,
				f_rng, p_rng));
	} while (mbedcrypto_bn_bit_count(&ctx->P) > nbits);

	/* T = T + count (updated cofactor) */
	if ((ret = mbedcrypto_bn_add_word(&T, &T, count)) != 0)
		goto cleanup;

	/* Find generator G: G = H^T mod P, G > 1 */
	if ((ret = mbedcrypto_bn_set_word(&H, 1)) != 0)
		goto cleanup;

	do {
		if ((ret = mbedcrypto_bn_add_word(&H, &H, 1)) != 0)
			goto cleanup;
		ret = mbedcrypto_bn_modpow(&ctx->G, &H, &T,
				&ctx->P, NULL);
		if (ret != 0)
			goto cleanup;
	} while (mbedcrypto_bn_cmp_word(&ctx->G, 1) == 0);

cleanup:
	mbedcrypto_bn_cleanup(&T);
	mbedcrypto_bn_cleanup(&H);
	mbedcrypto_bn_cleanup(&Q2);
	if (ret != 0) {
		mbedcrypto_bn_cleanup(&ctx->P);
		mbedcrypto_bn_cleanup(&ctx->Q);
		mbedcrypto_bn_cleanup(&ctx->G);
	}
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Key generation                                                     */
/* ------------------------------------------------------------------ */

int mbedcrypto_dsa_keygen(struct mbedcrypto_dsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int count = 0;
	int ret = 0;
	size_t q_len = 0;

	if (!ctx || !f_rng)
		return -EINVAL;

	if ((ret = dsa_check_params(ctx)) != 0)
		return ret;

	mbedcrypto_bn_init(&ctx->X);
	mbedcrypto_bn_init(&ctx->Y);

	q_len = mbedcrypto_bn_byte_count(&ctx->Q);

	/* Generate X in [1, Q - 1] */
	do {
		ret = mbedcrypto_bn_random(&ctx->X, q_len,
				f_rng, p_rng);
		if (ret != 0)
			goto cleanup;

		while (mbedcrypto_bn_cmp(&ctx->X, &ctx->Q) >= 0) {
			if ((ret = mbedcrypto_bn_rshift(&ctx->X, 1)) != 0)
				goto cleanup;
		}

		if (count++ > 10) {
			ret = -EAGAIN;
			goto cleanup;
		}
	} while (mbedcrypto_bn_cmp_word(&ctx->X, 1) < 0);

	/* Y = G^X mod P */
	ret = mbedcrypto_bn_modpow(&ctx->Y, &ctx->G, &ctx->X,
			&ctx->P, NULL);

cleanup:
	if (ret != 0) {
		mbedcrypto_bn_cleanup(&ctx->Y);
		mbedcrypto_bn_cleanup(&ctx->X);
	}
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Import / Export                                                     */
/* ------------------------------------------------------------------ */

int mbedcrypto_dsa_import_components(struct mbedcrypto_dsa_ctx *ctx,
		const uint8_t *P, size_t P_len,
		const uint8_t *Q, size_t Q_len,
		const uint8_t *G, size_t G_len,
		const uint8_t *Y, size_t Y_len,
		const uint8_t *X, size_t X_len)
{
	int ret = 0;

	if (!ctx)
		return -EINVAL;

	if (P) {
		ret = mbedcrypto_bn_from_binary(&ctx->P, P, P_len);
		if (ret != 0)
			return ret;
	}
	if (Q) {
		ret = mbedcrypto_bn_from_binary(&ctx->Q, Q, Q_len);
		if (ret != 0)
			return ret;
	}
	if (G) {
		ret = mbedcrypto_bn_from_binary(&ctx->G, G, G_len);
		if (ret != 0)
			return ret;
	}
	if (Y) {
		ret = mbedcrypto_bn_from_binary(&ctx->Y, Y, Y_len);
		if (ret != 0)
			return ret;
	}
	if (X) {
		ret = mbedcrypto_bn_from_binary(&ctx->X, X, X_len);
		if (ret != 0)
			return ret;
	}
	return 0;
}

int mbedcrypto_dsa_export_components(const struct mbedcrypto_dsa_ctx *ctx,
		uint8_t *P, size_t P_len,
		uint8_t *Q, size_t Q_len,
		uint8_t *G, size_t G_len,
		uint8_t *Y, size_t Y_len,
		uint8_t *X, size_t X_len)
{
	int ret = 0;

	if (!ctx)
		return -EINVAL;

	if (P) {
		ret = mbedcrypto_bn_to_binary(&ctx->P, P, P_len);
		if (ret != 0)
			return ret;
	}
	if (Q) {
		ret = mbedcrypto_bn_to_binary(&ctx->Q, Q, Q_len);
		if (ret != 0)
			return ret;
	}
	if (G) {
		ret = mbedcrypto_bn_to_binary(&ctx->G, G, G_len);
		if (ret != 0)
			return ret;
	}
	if (Y) {
		ret = mbedcrypto_bn_to_binary(&ctx->Y, Y, Y_len);
		if (ret != 0)
			return ret;
	}
	if (X) {
		ret = mbedcrypto_bn_to_binary(&ctx->X, X, X_len);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Sign (with blinding)                                               */
/* ------------------------------------------------------------------ */

int mbedcrypto_dsa_sign(struct mbedcrypto_dsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		unsigned int hashlen, const uint8_t *hash,
		uint8_t *sig, size_t *slen)
{
	int count = 0;
	int ret = 0;
	struct mbedcrypto_bignum B, K, H, R, S;
	size_t q_len = 0;

	if (!ctx || !f_rng || !hash ||
	    !sig || hashlen == 0)
		return -EINVAL;

	if ((ret = mbedcrypto_dsa_validate_privkey(ctx)) != 0)
		return ret;

	mbedcrypto_bn_init(&B);
	mbedcrypto_bn_init(&K);
	mbedcrypto_bn_init(&H);
	mbedcrypto_bn_init(&R);
	mbedcrypto_bn_init(&S);

	q_len = mbedcrypto_bn_byte_count(&ctx->Q);

	/* Generate K in [1, Q - 1] */
	do {
		if ((ret = mbedcrypto_bn_random(&K, q_len, f_rng, p_rng)) != 0)
			goto cleanup;

		while (mbedcrypto_bn_cmp(&K, &ctx->Q) >= 0) {
			if ((ret = mbedcrypto_bn_rshift(&K, 1)) != 0)
				goto cleanup;
		}

		if (count++ > 10) {
			ret = -EAGAIN;
			goto cleanup;
		}
	} while (mbedcrypto_bn_cmp_word(&K, 1) < 0);

	/* Generate blinding B in [1, Q - 1] */
	count = 0;
	do {
		if ((ret = mbedcrypto_bn_random(&B, q_len, f_rng, p_rng)) != 0)
			goto cleanup;

		while (mbedcrypto_bn_cmp(&B, &ctx->Q) >= 0) {
			if ((ret = mbedcrypto_bn_rshift(&B, 1)) != 0)
				goto cleanup;
		}

		if (count++ > 10) {
			ret = -EAGAIN;
			goto cleanup;
		}
	} while (mbedcrypto_bn_cmp_word(&B, 1) < 0);

	/* H = hash as bignum */
	if ((ret = mbedcrypto_bn_from_binary(&H, hash, hashlen)) != 0)
		goto cleanup;

	/* R = (G^K mod P) mod Q */
	if ((ret = mbedcrypto_bn_modpow(&R, &ctx->G, &K, &ctx->P, NULL)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&R, &R, &ctx->Q)) != 0)
		goto cleanup;

	/* FIPS 186 requires R != 0; if so, must retry with new K */
	if (mbedcrypto_bn_cmp_word(&R, 0) == 0) {
		ret = -EAGAIN;
		goto cleanup;
	}

	/*
	 * S = K^(-1) * (H + X*R) mod Q
	 *
	 * With blinding:
	 *   K' = (K*B)^(-1)
	 *   S = B * (K'*X*R + K'*H) mod Q
	 */

	/* K = (K*B)^(-1) mod Q */
	if ((ret = mbedcrypto_bn_mul(&K, &K, &B)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_modinv(&K, &K, &ctx->Q)) != 0)
		goto cleanup;

	/* S = K' * X * R mod Q */
	if ((ret = mbedcrypto_bn_mul(&S, &ctx->X, &R)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mul(&S, &S, &K)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&S, &S, &ctx->Q)) != 0)
		goto cleanup;

	/* H = K' * H mod Q */
	if ((ret = mbedcrypto_bn_mul(&H, &H, &K)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&H, &H, &ctx->Q)) != 0)
		goto cleanup;

	/* S = B * (S + H) mod Q */
	if ((ret = mbedcrypto_bn_add(&S, &S, &H)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mul(&S, &S, &B)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&S, &S, &ctx->Q)) != 0)
		goto cleanup;

	/* FIPS 186 requires S != 0; if so, must retry with new K */
	if (mbedcrypto_bn_cmp_word(&S, 0) == 0) {
		ret = -EAGAIN;
		goto cleanup;
	}

	/* Raw signature: r (q_len bytes) || s (q_len bytes) */
	ret = mbedcrypto_bn_to_binary(&R, sig, q_len);
	if (ret == 0)
		ret = mbedcrypto_bn_to_binary(&S, sig + q_len, q_len);
	if (ret == 0)
		*slen = 2 * q_len;

cleanup:
	mbedcrypto_bn_cleanup(&B);
	mbedcrypto_bn_cleanup(&K);
	mbedcrypto_bn_cleanup(&H);
	mbedcrypto_bn_cleanup(&R);
	mbedcrypto_bn_cleanup(&S);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Verify                                                             */
/* ------------------------------------------------------------------ */

int mbedcrypto_dsa_verify(struct mbedcrypto_dsa_ctx *ctx,
		unsigned int hashlen, const uint8_t *hash,
		const uint8_t *sig, size_t slen)
{
	int ret = 0;
	struct mbedcrypto_bignum U1, U2, W, R, S, V;
	size_t q_len = 0;

	if (!ctx || !hash || !sig || hashlen == 0)
		return -EINVAL;

	if ((ret = mbedcrypto_dsa_validate_pubkey(ctx)) != 0)
		return ret;

	q_len = mbedcrypto_bn_byte_count(&ctx->Q);

	/* Raw signature must be exactly 2 * q_len bytes */
	if (slen != 2 * q_len)
		return -EBADMSG;

	mbedcrypto_bn_init(&U1);
	mbedcrypto_bn_init(&U2);
	mbedcrypto_bn_init(&W);
	mbedcrypto_bn_init(&R);
	mbedcrypto_bn_init(&S);
	mbedcrypto_bn_init(&V);

	if ((ret = mbedcrypto_bn_from_binary(&R, sig, q_len)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_from_binary(&S, sig + q_len, q_len)) != 0)
		goto cleanup;

	/* Validate 0 < R < Q and 0 < S < Q */
	if (!(mbedcrypto_bn_cmp_word(&R, 0) > 0 &&
	      mbedcrypto_bn_cmp(&R, &ctx->Q) < 0) ||
	    !(mbedcrypto_bn_cmp_word(&S, 0) > 0 &&
	      mbedcrypto_bn_cmp(&S, &ctx->Q) < 0)) {
		ret = -EBADMSG;
		goto cleanup;
	}

	if ((ret = mbedcrypto_bn_from_binary(&U1, hash, hashlen)) != 0)
		goto cleanup;

	/* W = S^(-1) mod Q */
	if ((ret = mbedcrypto_bn_modinv(&W, &S, &ctx->Q)) != 0)
		goto cleanup;

	/* U1 = (hash * W) mod Q */
	if ((ret = mbedcrypto_bn_mul(&U1, &U1, &W)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&U1, &U1, &ctx->Q)) != 0)
		goto cleanup;

	/* U2 = (R * W) mod Q */
	if ((ret = mbedcrypto_bn_mul(&U2, &R, &W)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&U2, &U2, &ctx->Q)) != 0)
		goto cleanup;

	/* V = ((G^U1 * Y^U2) mod P) mod Q */
	if ((ret = mbedcrypto_bn_modpow(&S, &ctx->G, &U1, &ctx->P, NULL)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_modpow(&V, &ctx->Y, &U2, &ctx->P, NULL)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mul(&V, &S, &V)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&V, &V, &ctx->P)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&V, &V, &ctx->Q)) != 0)
		goto cleanup;

	if (mbedcrypto_bn_cmp(&V, &R) != 0)
		ret = -EBADMSG;
	else
		ret = 0;

cleanup:
	mbedcrypto_bn_cleanup(&U1);
	mbedcrypto_bn_cleanup(&U2);
	mbedcrypto_bn_cleanup(&W);
	mbedcrypto_bn_cleanup(&R);
	mbedcrypto_bn_cleanup(&S);
	mbedcrypto_bn_cleanup(&V);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  DER wrappers (reuse raw sign/verify)                               */
/* ------------------------------------------------------------------ */

int mbedcrypto_dsa_sign_der(struct mbedcrypto_dsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		unsigned int hashlen, const uint8_t *hash,
		uint8_t *sig, size_t sig_size, size_t *slen)
{
	struct mbedcrypto_bignum R, S;
	uint8_t raw[512];
	size_t raw_len = 0;
	size_t q_len = 0;
	uint8_t *p = NULL;
	int ret = 0;
	int len = 0;

	ret = mbedcrypto_dsa_sign(ctx, f_rng, p_rng,
			hashlen, hash, raw, &raw_len);
	if (ret != 0)
		return ret;

	q_len = raw_len / 2;
	mbedcrypto_bn_init(&R);
	mbedcrypto_bn_init(&S);

	if ((ret = mbedcrypto_bn_from_binary(&R, raw, q_len)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_from_binary(&S,
				raw + q_len, q_len)) != 0)
		goto cleanup;

	p = sig + sig_size;

	len = mbedcrypto_asn1_write_bn(&p, sig, &S);
	if (len < 0) { ret = len; goto cleanup; }

	ret = mbedcrypto_asn1_write_bn(&p, sig, &R);
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
	mbedcrypto_bn_cleanup(&R);
	mbedcrypto_bn_cleanup(&S);
	return ret;
}

int mbedcrypto_dsa_verify_der(struct mbedcrypto_dsa_ctx *ctx,
		unsigned int hashlen, const uint8_t *hash,
		const uint8_t *sig, size_t slen)
{
	struct mbedcrypto_bignum R, S;
	const uint8_t *p = sig;
	const uint8_t *end = sig + slen;
	size_t seq_len = 0, q_len = 0;
	uint8_t raw[512];
	int ret = 0;

	ret = mbedcrypto_asn1_read_tag(&p, end, &seq_len,
			MBEDCRYPTO_ASN1_SEQUENCE);
	if (ret != 0)
		return -EBADMSG;

	end = p + seq_len;

	mbedcrypto_bn_init(&R);
	mbedcrypto_bn_init(&S);

	if ((ret = mbedcrypto_asn1_read_bn(&p, end, &R)) != 0)
		goto fail;
	if ((ret = mbedcrypto_asn1_read_bn(&p, end, &S)) != 0)
		goto fail;

	q_len = mbedcrypto_bn_byte_count(&ctx->Q);

	if ((ret = mbedcrypto_bn_to_binary(&R, raw, q_len)) != 0)
		goto fail;
	if ((ret = mbedcrypto_bn_to_binary(&S,
				raw + q_len, q_len)) != 0)
		goto fail;

	mbedcrypto_bn_cleanup(&R);
	mbedcrypto_bn_cleanup(&S);
	return mbedcrypto_dsa_verify(ctx, hashlen, hash,
			raw, 2 * q_len);

fail:
	mbedcrypto_bn_cleanup(&R);
	mbedcrypto_bn_cleanup(&S);
	return -EBADMSG;
}
