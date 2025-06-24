// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * RSA public-key cryptography (PKCS#1 v1.5, OAEP, PSS)
 *
 * Key generation, import/export, encrypt/decrypt, sign/verify.
 * Uses CRT for private-key operations.
 */

#include <stdlib.h>
#include <string.h>

#include <mbedcrypto.h>

/* Max RSA key size in bytes (4096-bit) */
#define RSA_MAX_BYTES  512

/* ---------------------------------------------------------------------- */
/*  DigestInfo DER prefixes for PKCS#1 v1.5 signatures (RFC 8017 Sec.9.2) */
/* ---------------------------------------------------------------------- */

static const uint8_t md5_prefix[] = {
	0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
	0x04, 0x10
};

static const uint8_t sha1_prefix[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

static const uint8_t sha224_prefix[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
	0x00, 0x04, 0x1c
};

static const uint8_t sha256_prefix[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20
};

static const uint8_t sha384_prefix[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	0x00, 0x04, 0x30
};

static const uint8_t sha512_prefix[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
	0x00, 0x04, 0x40
};

/* SHA3 DigestInfo DER prefixes (OIDs from NIST, hash-of-hash per RFC 8702) */
static const uint8_t sha3_224_prefix[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
	0x00, 0x04, 0x1c
};

static const uint8_t sha3_256_prefix[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
	0x00, 0x04, 0x20
};

static const uint8_t sha3_384_prefix[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
	0x00, 0x04, 0x30
};

static const uint8_t sha3_512_prefix[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05,
	0x00, 0x04, 0x40
};

/* ------------------------------------------------------------------ */
/*  Hash helper                                                        */
/* ------------------------------------------------------------------ */

/* One-shot hash using unified API. */
static int rsa_hash(int hash_id, const uint8_t *in, size_t ilen,
		uint8_t *out)
{
	struct mbedcrypto_hash_ctx ctx;
	int ret = 0;

	ret = mbedcrypto_hash_init(&ctx, hash_id);
	if (ret != 0)
		return ret;
	mbedcrypto_hash_update(&ctx, in, ilen);
	ret = mbedcrypto_hash_final(&ctx, out);
	mbedcrypto_hash_cleanup(&ctx);
	return ret;
}

/* DigestInfo prefix for PKCS#1 v1.5. */
static const uint8_t *rsa_digest_prefix(int hash_id, size_t *plen)
{
	switch (hash_id) {
	case MBEDCRYPTO_RSA_HASH_MD5:
		*plen = sizeof(md5_prefix); return md5_prefix;
	case MBEDCRYPTO_RSA_HASH_SHA1:
		*plen = sizeof(sha1_prefix); return sha1_prefix;
	case MBEDCRYPTO_RSA_HASH_SHA224:
		*plen = sizeof(sha224_prefix); return sha224_prefix;
	case MBEDCRYPTO_RSA_HASH_SHA256:
		*plen = sizeof(sha256_prefix); return sha256_prefix;
	case MBEDCRYPTO_RSA_HASH_SHA384:
		*plen = sizeof(sha384_prefix); return sha384_prefix;
	case MBEDCRYPTO_RSA_HASH_SHA512:
		*plen = sizeof(sha512_prefix); return sha512_prefix;
	case MBEDCRYPTO_HASH_SHA3_224:
		*plen = sizeof(sha3_224_prefix); return sha3_224_prefix;
	case MBEDCRYPTO_HASH_SHA3_256:
		*plen = sizeof(sha3_256_prefix); return sha3_256_prefix;
	case MBEDCRYPTO_HASH_SHA3_384:
		*plen = sizeof(sha3_384_prefix); return sha3_384_prefix;
	case MBEDCRYPTO_HASH_SHA3_512:
		*plen = sizeof(sha3_512_prefix); return sha3_512_prefix;
	default:
		*plen = 0; return NULL;
	}
}

/* ---------------------------------------------------------------------- */
/*  MGF1 (Mask Generation Function, RFC 8017 Sec.B.2.1)                   */
/* ---------------------------------------------------------------------- */

static int mgf1(int hash_id, const uint8_t *seed, size_t slen,
		uint8_t *mask, size_t mlen)
{
	struct mbedcrypto_hash_ctx ctx;
	size_t hlen, off = 0, i;
	uint32_t counter = 0;
	int ret = 0;
	uint8_t cbuf[4];
	uint8_t hbuf[MBEDCRYPTO_SHA512_HASHSIZE]; /* max hash */

	hlen = mbedcrypto_hash_size(hash_id);
	if (hlen == 0)
		return -EINVAL;

	while (off < mlen) {
		cbuf[0] = counter >> 24;
		cbuf[1] = counter >> 16;
		cbuf[2] = counter >> 8;
		cbuf[3] = counter;

		ret = mbedcrypto_hash_init(&ctx, hash_id);
		if (ret != 0)
			return ret;
		mbedcrypto_hash_update(&ctx, seed, slen);
		mbedcrypto_hash_update(&ctx, cbuf, 4);
		ret = mbedcrypto_hash_final(&ctx, hbuf);
		mbedcrypto_hash_cleanup(&ctx);
		if (ret != 0)
			return ret;

		for (i = 0; i < hlen && off < mlen; i++, off++)
			mask[off] = hbuf[i];

		counter++;
	}

	memset(hbuf, 0, sizeof(hbuf));
	return 0;
}

/*
 * MGF1-XOR: compute MGF1(seed, mlen) and XOR it directly into buf[].
 * Avoids allocating a separate mask buffer on the stack.
 */
static int mgf1_xor(int hash_id, const uint8_t *seed, size_t slen,
		uint8_t *buf, size_t mlen)
{
	struct mbedcrypto_hash_ctx ctx;
	size_t hlen, off = 0, i;
	uint32_t counter = 0;
	int ret = 0;
	uint8_t cbuf[4];
	uint8_t hbuf[MBEDCRYPTO_SHA512_HASHSIZE];

	hlen = mbedcrypto_hash_size(hash_id);
	if (hlen == 0)
		return -EINVAL;

	while (off < mlen) {
		cbuf[0] = counter >> 24;
		cbuf[1] = counter >> 16;
		cbuf[2] = counter >> 8;
		cbuf[3] = counter;

		ret = mbedcrypto_hash_init(&ctx, hash_id);
		if (ret != 0)
			return ret;
		mbedcrypto_hash_update(&ctx, seed, slen);
		mbedcrypto_hash_update(&ctx, cbuf, 4);
		ret = mbedcrypto_hash_final(&ctx, hbuf);
		mbedcrypto_hash_cleanup(&ctx);
		if (ret != 0)
			return ret;

		for (i = 0; i < hlen && off < mlen; i++, off++)
			buf[off] ^= hbuf[i];

		counter++;
	}

	memset(hbuf, 0, sizeof(hbuf));
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

void mbedcrypto_rsa_init(struct mbedcrypto_rsa_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	mbedcrypto_bn_init(&ctx->N);
	mbedcrypto_bn_init(&ctx->E);
	mbedcrypto_bn_init(&ctx->D);
	mbedcrypto_bn_init(&ctx->P);
	mbedcrypto_bn_init(&ctx->Q);
	mbedcrypto_bn_init(&ctx->DP);
	mbedcrypto_bn_init(&ctx->DQ);
	mbedcrypto_bn_init(&ctx->QP);
	mbedcrypto_bn_init(&ctx->unblind);
	mbedcrypto_bn_init(&ctx->blind);
	mbedcrypto_bn_init(&ctx->RR_P);
	mbedcrypto_bn_init(&ctx->RR_Q);
	mbedcrypto_bn_init(&ctx->RR_N);
}

void mbedcrypto_rsa_cleanup(struct mbedcrypto_rsa_ctx *ctx)
{
	if (!ctx)
		return;
	mbedcrypto_bn_cleanup(&ctx->N);
	mbedcrypto_bn_cleanup(&ctx->E);
	mbedcrypto_bn_cleanup(&ctx->D);
	mbedcrypto_bn_cleanup(&ctx->P);
	mbedcrypto_bn_cleanup(&ctx->Q);
	mbedcrypto_bn_cleanup(&ctx->DP);
	mbedcrypto_bn_cleanup(&ctx->DQ);
	mbedcrypto_bn_cleanup(&ctx->QP);
	mbedcrypto_bn_cleanup(&ctx->unblind);
	mbedcrypto_bn_cleanup(&ctx->blind);
	mbedcrypto_bn_cleanup(&ctx->RR_P);
	mbedcrypto_bn_cleanup(&ctx->RR_Q);
	mbedcrypto_bn_cleanup(&ctx->RR_N);
	memset(ctx, 0, sizeof(*ctx));
}

void mbedcrypto_rsa_configure(struct mbedcrypto_rsa_ctx *ctx,
		int padding, int hash_id)
{
	ctx->padding = padding;
	ctx->hash_id = hash_id;
}

size_t mbedcrypto_rsa_len(const struct mbedcrypto_rsa_ctx *ctx)
{
	return mbedcrypto_bn_byte_count(&ctx->N);
}

/* ------------------------------------------------------------------ */
/*  Import / Complete                                                  */
/* ------------------------------------------------------------------ */

int mbedcrypto_rsa_import_components(struct mbedcrypto_rsa_ctx *ctx,
		const uint8_t *N, size_t N_len,
		const uint8_t *P, size_t P_len,
		const uint8_t *Q, size_t Q_len,
		const uint8_t *D, size_t D_len,
		const uint8_t *E, size_t E_len)
{
	int ret = 0;

	if (N && N_len) {
		ret = mbedcrypto_bn_from_binary(&ctx->N, N, N_len);
		if (ret != 0)
			return ret;
	}
	if (P && P_len) {
		ret = mbedcrypto_bn_from_binary(&ctx->P, P, P_len);
		if (ret != 0)
			return ret;
	}
	if (Q && Q_len) {
		ret = mbedcrypto_bn_from_binary(&ctx->Q, Q, Q_len);
		if (ret != 0)
			return ret;
	}
	if (D && D_len) {
		ret = mbedcrypto_bn_from_binary(&ctx->D, D, D_len);
		if (ret != 0)
			return ret;
	}
	if (E && E_len) {
		ret = mbedcrypto_bn_from_binary(&ctx->E, E, E_len);
		if (ret != 0)
			return ret;
	}

	return 0;
}

/*
 * Deduce primes P, Q from N, D, E.
 * Miller-Rabin factoring: DE-1 = 2^order * T, then try small bases.
 */
static int rsa_deduce_primes(struct mbedcrypto_rsa_ctx *ctx)
{
	static const uint8_t primes[] = {
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
		59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
		127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
		191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251
	};
	int ret = 0;
	unsigned int attempt = 0, iter = 0, order = 0;
	struct mbedcrypto_bignum T, K, G;

	mbedcrypto_bn_init(&T);
	mbedcrypto_bn_init(&K);
	mbedcrypto_bn_init(&G);

	/* T = D * E - 1 */
	if ((ret = mbedcrypto_bn_mul(&T, &ctx->D, &ctx->E)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_add_word(&T, &T, -1)) != 0)
		goto cleanup;

	/* Factor out powers of 2: T = 2^order * T_odd */
	order = 0;
	while (mbedcrypto_bn_test_bit(&T, 0) == 0) {
		order++;
		if ((ret = mbedcrypto_bn_rshift(&T, 1)) != 0)
			goto cleanup;
	}

	if (order == 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	/* Skip base 2 when N == 1 mod 8 */
	attempt = 0;
	if (ctx->N.data && (ctx->N.data[0] % 8 == 1))
		attempt = 1;

	for (; attempt < sizeof(primes); attempt++) {
		/* K = primes[attempt]^T mod N */
		if ((ret = mbedcrypto_bn_set_word(&K, primes[attempt])) != 0)
			goto cleanup;

		/* Check gcd(K, N) = 1 */
		if ((ret = mbedcrypto_bn_gcd(&G, &K, &ctx->N)) != 0)
			goto cleanup;
		if (mbedcrypto_bn_cmp_word(&G, 1) != 0)
			continue;

		if ((ret = mbedcrypto_bn_modpow(&K, &K, &T, &ctx->N, NULL)) != 0)
			goto cleanup;

		for (iter = 1; iter <= order; iter++) {
			if (mbedcrypto_bn_cmp_word(&K, 1) == 0)
				break;

			/* gcd(K + 1, N) */
			if ((ret = mbedcrypto_bn_add_word(&K, &K, 1)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_gcd(&G, &K, &ctx->N)) != 0)
				goto cleanup;

			if (mbedcrypto_bn_cmp_word(&G, 1) > 0 &&
			    mbedcrypto_bn_cmp(&G, &ctx->N) < 0) {
				/* Found P */
				if ((ret = mbedcrypto_bn_copy(&ctx->P, &G)) != 0)
					goto cleanup;
				ret = mbedcrypto_bn_div(&ctx->Q, NULL,
						&ctx->N, &ctx->P);
				goto cleanup;
			}

			/* K = (K - 1)^2 mod N */
			if ((ret = mbedcrypto_bn_add_word(&K, &K, -1)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_mul(&K, &K, &K)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_mod(&K, &K, &ctx->N)) != 0)
				goto cleanup;
		}

		if (mbedcrypto_bn_cmp_word(&K, 1) != 0)
			break; /* inconsistent inputs */
	}

	ret = -EINVAL;

cleanup:
	mbedcrypto_bn_cleanup(&T);
	mbedcrypto_bn_cleanup(&K);
	mbedcrypto_bn_cleanup(&G);
	return ret;
}

/*
 * Compute CRT parameters from P, Q, D:
 *   DP = D mod (P - 1)
 *   DQ = D mod (Q - 1)
 *   QP = Q^(-1) mod P
 */
static int rsa_deduce_crt(struct mbedcrypto_rsa_ctx *ctx)
{
	int ret = 0;
	struct mbedcrypto_bignum K;

	mbedcrypto_bn_init(&K);

	/* DP = D mod (P - 1) */
	if ((ret = mbedcrypto_bn_copy(&K, &ctx->P)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_add_word(&K, &K, -1)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&ctx->DP, &ctx->D, &K)) != 0)
		goto cleanup;

	/* DQ = D mod (Q - 1) */
	if ((ret = mbedcrypto_bn_copy(&K, &ctx->Q)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_add_word(&K, &K, -1)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&ctx->DQ, &ctx->D, &K)) != 0)
		goto cleanup;

	/* QP = Q^(-1) mod P */
	ret = mbedcrypto_bn_modinv(&ctx->QP, &ctx->Q, &ctx->P);

cleanup:
	mbedcrypto_bn_cleanup(&K);
	return ret;
}

int mbedcrypto_rsa_derive_crt(struct mbedcrypto_rsa_ctx *ctx)
{
	int ret = 0;
	int have_N  = (mbedcrypto_bn_cmp_word(&ctx->N, 0) != 0);
	int have_P  = (mbedcrypto_bn_cmp_word(&ctx->P, 0) != 0);
	int have_Q  = (mbedcrypto_bn_cmp_word(&ctx->Q, 0) != 0);
	int have_D  = (mbedcrypto_bn_cmp_word(&ctx->D, 0) != 0);
	int have_E  = (mbedcrypto_bn_cmp_word(&ctx->E, 0) != 0);

	/* Public-key only: N, E - nothing to complete. */
	if (have_N && have_E && !have_D && !have_P && !have_Q)
		return 0;

	/* Must have at least D and E */
	if (!have_D || !have_E)
		return -EINVAL;

	/* Compute N = P * Q if needed */
	if (!have_N && have_P && have_Q) {
		ret = mbedcrypto_bn_mul(&ctx->N, &ctx->P, &ctx->Q);
		if (ret != 0)
			return ret;
		have_N = 1;
	}

	/* Deduce P, Q from N, D, E */
	if (!have_P || !have_Q) {
		if (!have_N)
			return -EINVAL;
		ret = rsa_deduce_primes(ctx);
		if (ret != 0)
			return ret;
	}

	/* Compute CRT parameters */
	ret = rsa_deduce_crt(ctx);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Key generation                                                     */
/* ------------------------------------------------------------------ */

int mbedcrypto_rsa_keygen(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		unsigned int nbits, int exponent)
{
	int ret = 0;
	struct mbedcrypto_bignum P1, Q1, G, L;

	if (!f_rng || nbits < 1024 || (exponent < 3) ||
	    (exponent & 1) == 0)
		return -EINVAL;

	mbedcrypto_bn_init(&P1); mbedcrypto_bn_init(&Q1);
	mbedcrypto_bn_init(&G);
	mbedcrypto_bn_init(&L);

	/* E = exponent */
	if ((ret = mbedcrypto_bn_set_word(&ctx->E, exponent)) != 0)
		goto cleanup;

	/*
	 * Generate two strong primes P and Q with gcd(P-1, E) = 1
	 * and gcd(Q-1, E) = 1, each half the key size.
	 */
	do {
		ret = mbedcrypto_bn_gen_prime(&ctx->P, nbits / 2, 0,
				f_rng, p_rng);
		if (ret != 0)
			goto cleanup;

		ret = mbedcrypto_bn_gen_prime(&ctx->Q, nbits - nbits / 2, 0,
				f_rng, p_rng);
		if (ret != 0)
			goto cleanup;

		/* Ensure P > Q (swap if needed) */
		if (mbedcrypto_bn_cmp(&ctx->P, &ctx->Q) < 0)
			mbedcrypto_bn_swap(&ctx->P, &ctx->Q);

		/* Ensure P != Q */
		if (mbedcrypto_bn_cmp(&ctx->P, &ctx->Q) == 0)
			continue;

		/* N = P * Q */
		if ((ret = mbedcrypto_bn_mul(&ctx->N, &ctx->P, &ctx->Q)) != 0)
			goto cleanup;

		/* Check N has the right number of bits */
		if (mbedcrypto_bn_bit_count(&ctx->N) != nbits)
			continue;

		/* P1 = P - 1, Q1 = Q - 1 */
		if ((ret = mbedcrypto_bn_copy(&P1, &ctx->P)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_add_word(&P1, &P1, -1)) != 0)
			goto cleanup;

		if ((ret = mbedcrypto_bn_copy(&Q1, &ctx->Q)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_add_word(&Q1, &Q1, -1)) != 0)
			goto cleanup;

		/* Check gcd(P-1, E) = 1 */
		if ((ret = mbedcrypto_bn_gcd(&G, &P1, &ctx->E)) != 0)
			goto cleanup;
		if (mbedcrypto_bn_cmp_word(&G, 1) != 0)
			continue;

		/* Check gcd(Q-1, E) = 1 */
		if ((ret = mbedcrypto_bn_gcd(&G, &Q1, &ctx->E)) != 0)
			goto cleanup;
		if (mbedcrypto_bn_cmp_word(&G, 1) != 0)
			continue;

		/* L = lcm(P-1, Q-1) = (P-1)*(Q-1) / gcd(P-1, Q-1) */
		if ((ret = mbedcrypto_bn_gcd(&G, &P1, &Q1)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_mul(&L, &P1, &Q1)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_div(&L, NULL, &L, &G)) != 0)
			goto cleanup;

		/* D = E^(-1) mod L */
		if ((ret = mbedcrypto_bn_modinv(&ctx->D, &ctx->E, &L)) != 0)
			goto cleanup;

		/* Check D > 2^(nbits/2) for security */
		if (mbedcrypto_bn_bit_count(&ctx->D) <= nbits / 2)
			continue;

		break;
	} while (1);

	/* Compute CRT parameters */
	ret = rsa_deduce_crt(ctx);

cleanup:
	mbedcrypto_bn_cleanup(&P1); mbedcrypto_bn_cleanup(&Q1);
	mbedcrypto_bn_cleanup(&G);
	mbedcrypto_bn_cleanup(&L);

	if (ret != 0)
		mbedcrypto_rsa_cleanup(ctx);

	return ret;
}

/* ------------------------------------------------------------------ */
/*  Raw RSA public / private operations                                */
/* ------------------------------------------------------------------ */

int mbedcrypto_rsa_raw_public(struct mbedcrypto_rsa_ctx *ctx,
		const uint8_t *input, uint8_t *output)
{
	int ret = 0;
	size_t olen = 0;
	struct mbedcrypto_bignum T;

	olen = mbedcrypto_rsa_len(ctx);
	if (olen == 0)
		return -EINVAL;

	mbedcrypto_bn_init(&T);

	if ((ret = mbedcrypto_bn_from_binary(&T, input, olen)) != 0)
		goto cleanup;

	/* Verify input < N */
	if (mbedcrypto_bn_cmp(&T, &ctx->N) >= 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	/* T = T^E mod N */
	if ((ret = mbedcrypto_bn_modpow(&T, &T, &ctx->E, &ctx->N, &ctx->RR_N)) != 0)
		goto cleanup;

	ret = mbedcrypto_bn_to_binary(&T, output, olen);

cleanup:
	mbedcrypto_bn_cleanup(&T);
	return ret;
}

/*
 * Private-key operation using CRT:
 *   TP = input^DP mod P
 *   TQ = input^DQ mod Q
 *   T  = TQ + Q * ((TP - TQ) * QP mod P)
 *
 * Security features (when f_rng is provided):
 *   - Input blinding: T = T * Vf mod N, unblind after CRT
 *   - Exponent blinding: DP' = DP + r*(P-1), DQ' = DQ + s*(Q-1)
 *   - Fault-attack verification: check T^E mod N == original input
 *
 * Performance features:
 *   - Cached unblind/blind: generated once, then updated by squaring
 *   - Cached R^2 mod P/Q/N for Montgomery exponentiation
 */
int mbedcrypto_rsa_raw_private(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		const uint8_t *input, uint8_t *output)
{
	int ret = 0;
	size_t olen = 0;
	struct mbedcrypto_bignum T, TP, TQ, T1, T2;
	struct mbedcrypto_bignum I_save;    /* saved input for fault check */
	struct mbedcrypto_bignum *dp_use = &ctx->DP;
	struct mbedcrypto_bignum *dq_use = &ctx->DQ;
	struct mbedcrypto_bignum DP_b, DQ_b;
	struct mbedcrypto_bignum Pm1, Qm1, Rb;

	olen = mbedcrypto_rsa_len(ctx);
	if (olen == 0)
		return -EINVAL;

	mbedcrypto_bn_init(&T);
	mbedcrypto_bn_init(&TP);
	mbedcrypto_bn_init(&TQ);
	mbedcrypto_bn_init(&T1);
	mbedcrypto_bn_init(&T2);
	mbedcrypto_bn_init(&I_save);

	if ((ret = mbedcrypto_bn_from_binary(&T, input, olen)) != 0)
		goto cleanup;

	if (mbedcrypto_bn_cmp(&T, &ctx->N) >= 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	/* Save input for fault-attack verification */
	if (f_rng) {
		if ((ret = mbedcrypto_bn_copy(&I_save, &T)) != 0)
			goto cleanup;
	}

	/*
	 * RSA input blinding: T = T * Vf mod N.
	 *
	 * First call: generate fresh unblind, compute blind = Vi^E mod N,
	 * then unblind = Vi^(-1) mod N.
	 * Subsequent calls: update by squaring: unblind = Vi^2, blind = Vf^2.
	 */
	if (f_rng) {
		if (mbedcrypto_bn_cmp_word(&ctx->unblind, 0) == 0) {
			/* First call: generate fresh blinding pair */
			ret = mbedcrypto_bn_random(&ctx->unblind,
					mbedcrypto_bn_byte_count(&ctx->N),
					f_rng, p_rng);
			if (ret != 0)
				goto cleanup;

			ret = mbedcrypto_bn_modpow(&ctx->blind, &ctx->unblind,
					&ctx->E, &ctx->N, &ctx->RR_N);
			if (ret != 0)
				goto cleanup;

			if ((ret = mbedcrypto_bn_modinv(&ctx->unblind,
					&ctx->unblind, &ctx->N)) != 0)
				goto cleanup;
		} else {
			/* Subsequent calls: update by squaring */
			if ((ret = mbedcrypto_bn_mul(&ctx->unblind,
					&ctx->unblind, &ctx->unblind)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_mod(&ctx->unblind,
					&ctx->unblind, &ctx->N)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_mul(&ctx->blind,
					&ctx->blind, &ctx->blind)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_mod(&ctx->blind,
					&ctx->blind, &ctx->N)) != 0)
				goto cleanup;
		}

		if ((ret = mbedcrypto_bn_mul(&T, &T, &ctx->blind)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_mod(&T, &T, &ctx->N)) != 0)
			goto cleanup;
	}

	/*
	 * CRT computation with exponent blinding.
	 *
	 * When f_rng is available, blind the CRT exponents:
	 *   DP' = DP + r * (P - 1)
	 *   DQ' = DQ + s * (Q - 1)
	 * Mathematically equivalent by Fermat's little theorem,
	 * but randomizes the exponent to defeat DPA attacks.
	 *
	 * Use 32 bytes of random for the blinding factor (256 bits,
	 * sufficient to resist known side-channel attacks).
	 */
	{
		mbedcrypto_bn_init(&DP_b);
		mbedcrypto_bn_init(&DQ_b);

		if (f_rng) {
			mbedcrypto_bn_init(&Pm1);
			mbedcrypto_bn_init(&Qm1);
			mbedcrypto_bn_init(&Rb);

			/* DP_b = DP + Rb * (P - 1) */
			ret = mbedcrypto_bn_copy(&Pm1, &ctx->P);
			if (ret == 0)
				ret = mbedcrypto_bn_add_word(&Pm1, &Pm1, -1);
			if (ret == 0)
				ret = mbedcrypto_bn_random(&Rb, 32, f_rng, p_rng);
			if (ret == 0)
				ret = mbedcrypto_bn_mul(&DP_b, &Rb, &Pm1);
			if (ret == 0)
				ret = mbedcrypto_bn_add(&DP_b, &DP_b, &ctx->DP);

			/* DQ_b = DQ + Rb * (Q - 1) */
			if (ret == 0)
				ret = mbedcrypto_bn_copy(&Qm1, &ctx->Q);
			if (ret == 0)
				ret = mbedcrypto_bn_add_word(&Qm1, &Qm1, -1);
			if (ret == 0)
				ret = mbedcrypto_bn_random(&Rb, 32, f_rng, p_rng);
			if (ret == 0)
				ret = mbedcrypto_bn_mul(&DQ_b, &Rb, &Qm1);
			if (ret == 0)
				ret = mbedcrypto_bn_add(&DQ_b, &DQ_b, &ctx->DQ);

			mbedcrypto_bn_cleanup(&Pm1);
			mbedcrypto_bn_cleanup(&Qm1);
			mbedcrypto_bn_cleanup(&Rb);

			if (ret != 0) {
				mbedcrypto_bn_cleanup(&DP_b);
				mbedcrypto_bn_cleanup(&DQ_b);
				goto cleanup;
			}

			dp_use = &DP_b;
			dq_use = &DQ_b;
		}

		/* TP = T^DP mod P (with cached R^2 mod P) */
		ret = mbedcrypto_bn_mod(&TP, &T, &ctx->P);
		if (ret == 0)
			ret = mbedcrypto_bn_modpow(&TP, &TP, dp_use,
				&ctx->P, &ctx->RR_P);

		/* TQ = T^DQ mod Q (with cached R^2 mod Q) */
		if (ret == 0)
			ret = mbedcrypto_bn_mod(&TQ, &T, &ctx->Q);
		if (ret == 0)
			ret = mbedcrypto_bn_modpow(&TQ, &TQ, dq_use,
				&ctx->Q, &ctx->RR_Q);

		mbedcrypto_bn_cleanup(&DP_b);
		mbedcrypto_bn_cleanup(&DQ_b);

		if (ret != 0)
			goto cleanup;
	}

	/* T = TQ + Q * ((TP - TQ) * QP mod P) */
	if ((ret = mbedcrypto_bn_sub(&T1, &TP, &TQ)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mul(&T1, &T1, &ctx->QP)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&T1, &T1, &ctx->P)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mul(&T1, &T1, &ctx->Q)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_add(&T, &TQ, &T1)) != 0)
		goto cleanup;

	/* Unblind: T = T * Vi mod N */
	if (f_rng) {
		if ((ret = mbedcrypto_bn_mul(&T, &T, &ctx->unblind)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_mod(&T, &T, &ctx->N)) != 0)
			goto cleanup;

		/* Fault-attack verification: T^E mod N must match input */
		ret = mbedcrypto_bn_modpow(&T2, &T, &ctx->E,
				&ctx->N, &ctx->RR_N);
		if (ret != 0)
			goto cleanup;
		if (mbedcrypto_bn_cmp(&T2, &I_save) != 0) {
			ret = -EINVAL;
			goto cleanup;
		}
	}

	ret = mbedcrypto_bn_to_binary(&T, output, olen);

cleanup:
	mbedcrypto_bn_cleanup(&T);
	mbedcrypto_bn_cleanup(&TP);
	mbedcrypto_bn_cleanup(&TQ);
	mbedcrypto_bn_cleanup(&T1);
	mbedcrypto_bn_cleanup(&T2);
	mbedcrypto_bn_cleanup(&I_save);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  PKCS#1 v1.5 encryption / decryption                               */
/* ------------------------------------------------------------------ */

static int rsa_pkcs15_encrypt(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		size_t ilen, const uint8_t *input,
		uint8_t *output)
{
	int ret = 0;
	size_t i = 0, olen = 0, nb_pad = 0;
	uint8_t *p = NULL;

	olen = mbedcrypto_rsa_len(ctx);

	/* olen = 0x00 || 0x02 || PS (>= 8 bytes) || 0x00 || M */
	if (olen < ilen + 11)
		return -EINVAL;

	nb_pad = olen - 3 - ilen;
	p = output;

	*p++ = 0x00;
	*p++ = 0x02;

	/* Generate non-zero random padding */
	if ((ret = f_rng(p_rng, p, nb_pad)) != 0)
		return ret;

	for (i = 0; i < nb_pad; i++) {
		while (p[i] == 0) {
			if ((ret = f_rng(p_rng, &p[i], 1)) != 0)
				return ret;
		}
	}
	p += nb_pad;

	*p++ = 0x00;
	if (ilen)
		memcpy(p, input, ilen);

	return mbedcrypto_rsa_raw_public(ctx, output, output);
}

static int rsa_pkcs15_decrypt(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		size_t *olen, const uint8_t *input,
		uint8_t *output, size_t output_max_len)
{
	int ret = 0;
	size_t ilen = 0, pad_count = 0;
	size_t i = 0, sep = 0, found = 0;
	size_t eq_zero = 0, first_zero = 0;
	uint8_t *p = NULL;
	uint8_t bad = 0;
	uint8_t buf[RSA_MAX_BYTES];

	ilen = mbedcrypto_rsa_len(ctx);
	if (ilen < 11 || ilen > RSA_MAX_BYTES)
		return -EINVAL;

	if ((ret = mbedcrypto_rsa_raw_private(ctx, f_rng, p_rng,
					      input, buf)) != 0)
		goto cleanup;

	/* Verify PKCS#1 v1.5 padding: 0x00 0x02 <PS> 0x00 <M> */
	bad = buf[0] | (buf[1] ^ 0x02);

	/*
	 * Constant-time scan for the 0x00 separator byte.
	 * Always iterates over the entire buffer to avoid
	 * Bleichenbacher-style timing oracles.
	 */
	sep = 0;
	found = 0;
	for (i = 2; i < ilen; i++) {
		eq_zero = 1 ^ (((size_t)buf[i] |
			(0 - (size_t)buf[i])) >> (sizeof(size_t) * 8 - 1));
		first_zero = eq_zero & (1 ^ found);
		sep ^= (sep ^ i) & (0 - first_zero);
		found |= eq_zero;
	}

	pad_count = sep - 2;

	/* PS must be at least 8 bytes, and separator must be found */
	bad |= (found == 0) ? 1 : 0;
	bad |= (pad_count < 8) ? 1 : 0;

	if (bad) {
		ret = -EBADMSG;
		goto cleanup;
	}

	p = buf + sep + 1; /* skip past the 0x00 separator */
	*olen = buf + ilen - p;

	if (*olen > output_max_len) {
		ret = -EINVAL;
		goto cleanup;
	}

	memcpy(output, p, *olen);

cleanup:
	memset(buf, 0, ilen);
	return ret;
}

/* --------------------------------------------------------------------- */
/*  OAEP encryption / decryption (PKCS#1 v2.1, RFC 8017 Sec.7.1)         */
/* --------------------------------------------------------------------- */

static int rsa_oaep_encrypt(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		size_t ilen, const uint8_t *input,
		uint8_t *output)
{
	int ret = 0;
	int mgf_id = 0;
	size_t hlen = 0, olen = 0, db_len = 0, ps_len = 0, i = 0;
	uint8_t *seed = NULL, *db = NULL, *p = NULL;
	uint8_t lhash[MBEDCRYPTO_SHA512_HASHSIZE];
	uint8_t mask_seed[MBEDCRYPTO_SHA512_HASHSIZE];

	mgf_id = ctx->mgf_hash_id ? ctx->mgf_hash_id : ctx->hash_id;

	hlen = mbedcrypto_hash_size(ctx->hash_id);
	if (hlen == 0)
		return -EINVAL;

	olen = mbedcrypto_rsa_len(ctx);
	if (olen > RSA_MAX_BYTES)
		return -EINVAL;

	/* mLen <= k - 2*hLen - 2 */
	if (olen < 2 * hlen + 2 + ilen)
		return -EINVAL;

	/* Hash label (empty string) */
	ret = rsa_hash(ctx->hash_id, (const uint8_t *)"", 0, lhash);
	if (ret != 0)
		return ret;

	db_len = olen - hlen - 1;
	ps_len = db_len - hlen - 1 - ilen;

	/* Build EM = 0x00 || maskedSeed || maskedDB */
	memset(output, 0, olen);
	seed = output + 1;
	db = seed + hlen;

	/* Build DB directly in output: lHash || PS (zeros) || 0x01 || M */
	p = db;
	memcpy(p, lhash, hlen);
	p += hlen;
	/* PS is already zero from memset */
	p += ps_len;
	*p++ = 0x01;
	if (ilen)
		memcpy(p, input, ilen);

	/* Generate random seed */
	if ((ret = f_rng(p_rng, seed, hlen)) != 0)
		return ret;

	/* maskedDB = DB XOR MGF1(seed, db_len) */
	if ((ret = mgf1_xor(mgf_id, seed, hlen, db, db_len)) != 0)
		return ret;

	/* seedMask = MGF1(maskedDB, hlen) */
	ret = mgf1(mgf_id, db, db_len, mask_seed, hlen);
	if (ret != 0)
		return ret;

	/* maskedSeed = seed XOR seedMask */
	for (i = 0; i < hlen; i++)
		seed[i] ^= mask_seed[i];

	return mbedcrypto_rsa_raw_public(ctx, output, output);
}

static int rsa_oaep_decrypt(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		size_t *olen, const uint8_t *input,
		uint8_t *output, size_t output_max_len)
{
	int ret = 0;
	int mgf_id = 0;
	size_t hlen = 0, i = 0, klen = 0, db_len = 0;
	uint8_t *seed = NULL, *db = NULL, *p = NULL;
	uint8_t lhash[MBEDCRYPTO_SHA512_HASHSIZE];
	uint8_t seed_mask[MBEDCRYPTO_SHA512_HASHSIZE];
	uint8_t bad = 0;
	uint8_t buf[RSA_MAX_BYTES];

	mgf_id = ctx->mgf_hash_id ? ctx->mgf_hash_id : ctx->hash_id;

	hlen = mbedcrypto_hash_size(ctx->hash_id);
	if (hlen == 0)
		return -EINVAL;

	klen = mbedcrypto_rsa_len(ctx);
	if (klen < 2 * hlen + 2 || klen > RSA_MAX_BYTES)
		return -EINVAL;

	if ((ret = mbedcrypto_rsa_raw_private(ctx, f_rng, p_rng,
					      input, buf)) != 0)
		goto cleanup;

	/* EM = 0x00 || maskedSeed || maskedDB */
	bad = buf[0]; /* must be 0x00 */

	seed = buf + 1;
	db = seed + hlen;
	db_len = klen - hlen - 1;

	/* seedMask = MGF1(maskedDB, hlen) */
	if ((ret = mgf1(mgf_id, db, db_len, seed_mask, hlen)) != 0)
		goto cleanup;

	/* seed = maskedSeed XOR seedMask */
	for (i = 0; i < hlen; i++)
		seed[i] ^= seed_mask[i];

	/* DB = maskedDB XOR MGF1(seed, db_len) */
	if ((ret = mgf1_xor(mgf_id, seed, hlen, db, db_len)) != 0)
		goto cleanup;

	/* DB = lHash' || PS (0x00...) || 0x01 || M */
	/* Hash empty label */
	if ((ret = rsa_hash(ctx->hash_id,
			    (const uint8_t *)"", 0, lhash)) != 0)
		goto cleanup;

	/* Check lHash' matches */
	bad |= mbedcrypto_ct_memcmp(db, lhash, hlen) ? 1 : 0;

	/* Find 0x01 separator */
	{
		p = db + hlen;

		while (p < db + db_len && *p == 0)
			p++;
		if (p >= db + db_len || *p != 0x01)
			bad = 1;
		else {
			p++; /* skip 0x01 */
			*olen = db + db_len - p;
			if (*olen > output_max_len)
				bad = 1;
			else if (!bad)
				memcpy(output, p, *olen);
		}
	}

	if (bad)
		ret = -EBADMSG;

cleanup:
	memset(buf, 0, klen);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  PKCS#1 v1.5 sign / verify                                         */
/* ------------------------------------------------------------------ */

static int rsa_pkcs15_sign(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		int hash_id, size_t hashlen,
		const uint8_t *hash, uint8_t *sig)
{
	size_t olen = 0, prefix_len = 0, nb_pad = 0;
	const uint8_t *prefix;
	uint8_t *p = NULL;

	olen = mbedcrypto_rsa_len(ctx);

	prefix = rsa_digest_prefix(hash_id, &prefix_len);
	if (!prefix)
		return -EINVAL;

	/* EM: 0x00 0x01 <PS (0xFF)> 0x00 <DigestInfo> */
	/* DigestInfo = prefix || hash */
	if (olen < prefix_len + hashlen + 11)
		return -EINVAL;

	nb_pad = olen - 3 - prefix_len - hashlen;

	p = sig;
	*p++ = 0x00;
	*p++ = 0x01;
	memset(p, 0xFF, nb_pad);
	p += nb_pad;
	*p++ = 0x00;
	memcpy(p, prefix, prefix_len);
	p += prefix_len;
	memcpy(p, hash, hashlen);

	return mbedcrypto_rsa_raw_private(ctx, f_rng, p_rng, sig, sig);
}

static int rsa_pkcs15_verify(struct mbedcrypto_rsa_ctx *ctx,
		int hash_id, size_t hashlen,
		const uint8_t *hash, const uint8_t *sig)
{
	int ret = 0;
	size_t olen = 0, prefix_len = 0, nb_pad = 0, i = 0;
	const uint8_t *prefix;
	uint8_t *p = NULL;
	uint8_t buf[RSA_MAX_BYTES];

	olen = mbedcrypto_rsa_len(ctx);
	if (olen > RSA_MAX_BYTES)
		return -EINVAL;

	prefix = rsa_digest_prefix(hash_id, &prefix_len);
	if (!prefix)
		return -EINVAL;

	if (olen < prefix_len + hashlen + 11)
		return -EINVAL;

	if ((ret = mbedcrypto_rsa_raw_public(ctx, sig, buf)) != 0)
		goto cleanup;

	/* Rebuild expected EM and compare */
	nb_pad = olen - 3 - prefix_len - hashlen;

	p = buf;
	if (*p++ != 0x00 || *p++ != 0x01) {
		ret = -EBADMSG;
		goto cleanup;
	}

	/* Check padding bytes */
	for (i = 0; i < nb_pad; i++) {
		if (*p++ != 0xFF) {
			ret = -EBADMSG;
			goto cleanup;
		}
	}

	if (*p++ != 0x00) {
		ret = -EBADMSG;
		goto cleanup;
	}

	/* Compare DigestInfo prefix (constant-time) */
	if (mbedcrypto_ct_memcmp(p, prefix, prefix_len) != 0) {
		ret = -EBADMSG;
		goto cleanup;
	}
	p += prefix_len;

	/* Compare hash */
	if (mbedcrypto_ct_memcmp(p, hash, hashlen) != 0) {
		ret = -EBADMSG;
		goto cleanup;
	}

	ret = 0;

cleanup:
	memset(buf, 0, olen);
	return ret;
}

/* --------------------------------------------------------------------- */
/*  PSS sign / verify (PKCS#1 v2.1, RFC 8017 Sec.8.1)                    */
/* --------------------------------------------------------------------- */

static int rsa_pss_sign(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		int hash_id, size_t hashlen,
		const uint8_t *hash, uint8_t *sig)
{
	struct mbedcrypto_hash_ctx hctx;
	int ret = 0;
	size_t hlen = 0, olen = 0, emlen = 0, salt_len = 0, db_len = 0, msb = 0;
	uint8_t *em = NULL, *db = NULL, *h = NULL;
	uint8_t salt[MBEDCRYPTO_SHA512_HASHSIZE];
	static const uint8_t zeros[8] = {0};

	hlen = mbedcrypto_hash_size(hash_id);
	if (hlen == 0 || hlen != hashlen)
		return -EINVAL;

	olen = mbedcrypto_rsa_len(ctx);
	if (olen > RSA_MAX_BYTES)
		return -EINVAL;

	msb = mbedcrypto_bn_bit_count(&ctx->N) - 1;
	emlen = (msb + 7) / 8;

	/* salt_len = hlen (standard choice) */
	salt_len = hlen;

	/* emLen >= hLen + sLen + 2 */
	if (emlen < hlen + salt_len + 2)
		return -EINVAL;

	em = sig + olen - emlen;
	memset(sig, 0, olen);

	db_len = emlen - hlen - 1;
	db = em;
	h = em + db_len;

	/* Generate salt */
	ret = f_rng(p_rng, salt, salt_len);
	if (ret != 0)
		return ret;

	/* H = Hash(0x00..00 || mHash || salt) - streamed to avoid m_prime[] */
	{
		ret = mbedcrypto_hash_init(&hctx, hash_id);
		if (ret != 0)
			return ret;
		mbedcrypto_hash_update(&hctx, zeros, 8);
		mbedcrypto_hash_update(&hctx, hash, hashlen);
		mbedcrypto_hash_update(&hctx, salt, salt_len);
		ret = mbedcrypto_hash_final(&hctx, h);
		mbedcrypto_hash_cleanup(&hctx);
		if (ret != 0)
			return ret;
	}

	/* DB = PS (zeros) || 0x01 || salt */
	memset(db, 0, db_len - salt_len - 1);
	db[db_len - salt_len - 1] = 0x01;
	memcpy(db + db_len - salt_len, salt, salt_len);

	/* maskedDB = DB XOR MGF1(H, db_len) */
	if ((ret = mgf1_xor(hash_id, h, hlen, db, db_len)) != 0)
		return ret;

	/* Set the leftmost 8*emLen - emBits bits of maskedDB to zero */
	if (msb % 8)
		db[0] &= 0xFF >> (8 - msb % 8);

	/* 0xBC trailer */
	em[emlen - 1] = 0xBC;

	return mbedcrypto_rsa_raw_private(ctx, f_rng, p_rng, sig, sig);
}

static int rsa_pss_verify(struct mbedcrypto_rsa_ctx *ctx,
		int hash_id, size_t hashlen,
		const uint8_t *hash, const uint8_t *sig)
{
	struct mbedcrypto_hash_ctx hctx;
	int ret = 0;
	size_t hlen = 0, olen = 0, emlen = 0, db_len = 0, salt_len = 0, msb = 0, j = 0;
	uint8_t *em = NULL, *db = NULL, *h = NULL;
	uint8_t hcheck[MBEDCRYPTO_SHA512_HASHSIZE];
	uint8_t buf[RSA_MAX_BYTES];
	static const uint8_t zeros[8] = {0};

	hlen = mbedcrypto_hash_size(hash_id);
	if (hlen == 0 || hlen != hashlen)
		return -EINVAL;

	olen = mbedcrypto_rsa_len(ctx);
	if (olen > RSA_MAX_BYTES)
		return -EINVAL;

	msb = mbedcrypto_bn_bit_count(&ctx->N) - 1;
	emlen = (msb + 7) / 8;

	if (emlen < hlen + 2)
		return -EBADMSG;

	if ((ret = mbedcrypto_rsa_raw_public(ctx, sig, buf)) != 0)
		goto cleanup;

	em = buf + olen - emlen;

	/* Check trailer byte */
	if (em[emlen - 1] != 0xBC) {
		ret = -EBADMSG;
		goto cleanup;
	}

	db_len = emlen - hlen - 1;
	db = em;
	h = em + db_len;

	/* Check leftmost bits are zero */
	if (msb % 8) {
		if (db[0] & ~(0xFF >> (8 - msb % 8))) {
			ret = -EBADMSG;
			goto cleanup;
		}
	}

	/* DB = maskedDB XOR MGF1(H, db_len) */
	if ((ret = mgf1_xor(hash_id, h, hlen, db, db_len)) != 0)
		goto cleanup;

	/* Set leftmost bits to zero */
	if (msb % 8)
		db[0] &= 0xFF >> (8 - msb % 8);

	/* DB = PS (zeros) || 0x01 || salt */
	/* Find 0x01 separator */
	{
		for (j = 0; j < db_len; j++) {
			if (db[j] == 0x01)
				break;
			if (db[j] != 0x00) {
				ret = -EBADMSG;
				goto cleanup;
			}
		}
		if (j >= db_len) {
			ret = -EBADMSG;
			goto cleanup;
		}

		salt_len = db_len - j - 1;
	}

	/* H' = Hash(0x00..00 || mHash || salt) - streamed */
	{
		ret = mbedcrypto_hash_init(&hctx, hash_id);
		if (ret != 0)
			goto cleanup;
		mbedcrypto_hash_update(&hctx, zeros, 8);
		mbedcrypto_hash_update(&hctx, hash, hashlen);
		mbedcrypto_hash_update(&hctx, db + db_len - salt_len,
				       salt_len);
		ret = mbedcrypto_hash_final(&hctx, hcheck);
		mbedcrypto_hash_cleanup(&hctx);
		if (ret != 0)
			goto cleanup;
	}

	if (mbedcrypto_ct_memcmp(h, hcheck, hlen) != 0)
		ret = -EBADMSG;
	else
		ret = 0;

cleanup:
	memset(buf, 0, olen);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Dispatch wrappers                                                  */
/* ------------------------------------------------------------------ */

int mbedcrypto_rsa_encrypt(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		size_t ilen, const uint8_t *input,
		uint8_t *output)
{
	if (ctx->padding == MBEDCRYPTO_RSA_PKCS1_V21)
		return rsa_oaep_encrypt(ctx, f_rng, p_rng,
				ilen, input, output);
	else
		return rsa_pkcs15_encrypt(ctx, f_rng, p_rng,
				ilen, input, output);
}

int mbedcrypto_rsa_decrypt(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		size_t *olen, const uint8_t *input,
		uint8_t *output, size_t output_max_len)
{
	if (ctx->padding == MBEDCRYPTO_RSA_PKCS1_V21)
		return rsa_oaep_decrypt(ctx, f_rng, p_rng,
				olen, input, output, output_max_len);
	else
		return rsa_pkcs15_decrypt(ctx, f_rng, p_rng,
				olen, input, output, output_max_len);
}

int mbedcrypto_rsa_sign(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		int hash_id, size_t hashlen,
		const uint8_t *hash, uint8_t *sig)
{
	if (ctx->padding == MBEDCRYPTO_RSA_PKCS1_V21)
		return rsa_pss_sign(ctx, f_rng, p_rng,
				hash_id, hashlen, hash, sig);
	else
		return rsa_pkcs15_sign(ctx, f_rng, p_rng,
				hash_id, hashlen, hash, sig);
}

int mbedcrypto_rsa_verify(struct mbedcrypto_rsa_ctx *ctx,
		int hash_id, size_t hashlen,
		const uint8_t *hash, const uint8_t *sig)
{
	if (ctx->padding == MBEDCRYPTO_RSA_PKCS1_V21)
		return rsa_pss_verify(ctx, hash_id, hashlen, hash, sig);
	else
		return rsa_pkcs15_verify(ctx, hash_id, hashlen, hash, sig);
}
