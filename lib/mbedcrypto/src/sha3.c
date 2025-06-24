// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SHA-3 (Keccak) hash family (FIPS 202)
 *
 * Implements Keccak-f[1600] permutation with sponge construction
 * for SHA3-224, SHA3-256, SHA3-384 and SHA3-512.
 */

#include <string.h>

#include <mbedcrypto/sha3.h>

/* Rate in bytes for each SHA-3/SHAKE variant */
static const size_t sha3_rate[] = {
	[MBEDCRYPTO_SHA3_224] = 200 - 2 * 28,  /* 144 */
	[MBEDCRYPTO_SHA3_256] = 200 - 2 * 32,  /* 136 */
	[MBEDCRYPTO_SHA3_384] = 200 - 2 * 48,  /* 104 */
	[MBEDCRYPTO_SHA3_512] = 200 - 2 * 64,  /*  72 */
	[MBEDCRYPTO_SHAKE256] = 136,            /* same as SHA3-256 */
};

/* Output length in bytes (0 = XOF / variable) */
static const size_t sha3_olen[] = {
	[MBEDCRYPTO_SHA3_224] = 28,
	[MBEDCRYPTO_SHA3_256] = 32,
	[MBEDCRYPTO_SHA3_384] = 48,
	[MBEDCRYPTO_SHA3_512] = 64,
	[MBEDCRYPTO_SHAKE256] = 0,  /* variable */
};

/* Domain separator byte */
static const uint8_t sha3_dsep[] = {
	[MBEDCRYPTO_SHA3_224] = 0x06,
	[MBEDCRYPTO_SHA3_256] = 0x06,
	[MBEDCRYPTO_SHA3_384] = 0x06,
	[MBEDCRYPTO_SHA3_512] = 0x06,
	[MBEDCRYPTO_SHAKE256] = 0x1f,
};

/* Keccak round constants (24 rounds) */
static const uint64_t keccak_rc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL,
	0x800000000000808aULL, 0x8000000080008000ULL,
	0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008aULL, 0x0000000000000088ULL,
	0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL,
	0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL,
	0x0000000080000001ULL, 0x8000000080008008ULL,
};

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/*
 * Keccak-f[1600] permutation: 24 rounds of theta-rho-pi-chi-iota.
 *
 * Fully unrolled theta/chi (no modulo, no inner loops).
 * In-place rho-pi via single-cycle swap chain (no temp[25] array).
 * The 24 non-trivial positions form one permutation cycle:
 *   1->10->7->11->17->18->3->5->16->8->21->24->4->15->23->19->13->12->2->20->14->22->9->6->1
 * Processed in reverse (inverse-pi order) for in-place operation.
 */
static void keccak_f1600(uint64_t s[25])
{
	uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0;
	uint64_t t = 0, t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
	int round = 0;

	for (round = 0; round < 24; round++) {
		/* theta */
		c0 = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
		c1 = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
		c2 = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
		c3 = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
		c4 = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];

		t = c4 ^ ROTL64(c1, 1);
		s[0] ^= t; s[5] ^= t; s[10] ^= t; s[15] ^= t; s[20] ^= t;
		t = c0 ^ ROTL64(c2, 1);
		s[1] ^= t; s[6] ^= t; s[11] ^= t; s[16] ^= t; s[21] ^= t;
		t = c1 ^ ROTL64(c3, 1);
		s[2] ^= t; s[7] ^= t; s[12] ^= t; s[17] ^= t; s[22] ^= t;
		t = c2 ^ ROTL64(c4, 1);
		s[3] ^= t; s[8] ^= t; s[13] ^= t; s[18] ^= t; s[23] ^= t;
		t = c3 ^ ROTL64(c0, 1);
		s[4] ^= t; s[9] ^= t; s[14] ^= t; s[19] ^= t; s[24] ^= t;

		/* rho-pi: in-place single-cycle swap chain */
		t = ROTL64(s[1], 1);
		s[1]  = ROTL64(s[6],  44); s[6]  = ROTL64(s[9],  20);
		s[9]  = ROTL64(s[22], 61); s[22] = ROTL64(s[14], 39);
		s[14] = ROTL64(s[20], 18); s[20] = ROTL64(s[2],  62);
		s[2]  = ROTL64(s[12], 43); s[12] = ROTL64(s[13], 25);
		s[13] = ROTL64(s[19],  8); s[19] = ROTL64(s[23], 56);
		s[23] = ROTL64(s[15], 41); s[15] = ROTL64(s[4],  27);
		s[4]  = ROTL64(s[24], 14); s[24] = ROTL64(s[21],  2);
		s[21] = ROTL64(s[8],  55); s[8]  = ROTL64(s[16], 45);
		s[16] = ROTL64(s[5],  36); s[5]  = ROTL64(s[3],  28);
		s[3]  = ROTL64(s[18], 21); s[18] = ROTL64(s[17], 15);
		s[17] = ROTL64(s[11], 10); s[11] = ROTL64(s[7],   6);
		s[7]  = ROTL64(s[10],  3); s[10] = t;

		/* chi: row-by-row non-linear mixing */
		t0 = s[0]; t1 = s[1]; t2 = s[2]; t3 = s[3]; t4 = s[4];
		s[0] ^= ~t1 & t2; s[1] ^= ~t2 & t3; s[2] ^= ~t3 & t4;
		s[3] ^= ~t4 & t0; s[4] ^= ~t0 & t1;

		t0 = s[5]; t1 = s[6]; t2 = s[7]; t3 = s[8]; t4 = s[9];
		s[5] ^= ~t1 & t2; s[6] ^= ~t2 & t3; s[7] ^= ~t3 & t4;
		s[8] ^= ~t4 & t0; s[9] ^= ~t0 & t1;

		t0 = s[10]; t1 = s[11]; t2 = s[12]; t3 = s[13]; t4 = s[14];
		s[10] ^= ~t1 & t2; s[11] ^= ~t2 & t3; s[12] ^= ~t3 & t4;
		s[13] ^= ~t4 & t0; s[14] ^= ~t0 & t1;

		t0 = s[15]; t1 = s[16]; t2 = s[17]; t3 = s[18]; t4 = s[19];
		s[15] ^= ~t1 & t2; s[16] ^= ~t2 & t3; s[17] ^= ~t3 & t4;
		s[18] ^= ~t4 & t0; s[19] ^= ~t0 & t1;

		t0 = s[20]; t1 = s[21]; t2 = s[22]; t3 = s[23]; t4 = s[24];
		s[20] ^= ~t1 & t2; s[21] ^= ~t2 & t3; s[22] ^= ~t3 & t4;
		s[23] ^= ~t4 & t0; s[24] ^= ~t0 & t1;

		/* iota */
		s[0] ^= keccak_rc[round];
	}
}

/* Absorb rate-sized block into state (XOR then permute) */
static void keccak_absorb(uint64_t state[25],
		const uint8_t *block, size_t rate)
{
	size_t lanes = rate / 8;
	size_t i = 0;
	uint64_t lane = 0;

	for (i = 0; i < lanes; i++) {
		memcpy(&lane, block + 8 * i, 8);
		state[i] ^= lane;
	}

	keccak_f1600(state);
}

void mbedcrypto_sha3_init(struct mbedcrypto_sha3_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_sha3_start(struct mbedcrypto_sha3_ctx *ctx, int type)
{
	if (!ctx)
		return -EINVAL;
	if (type < MBEDCRYPTO_SHA3_224 || type > MBEDCRYPTO_SHAKE256)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->rate = sha3_rate[type];
	ctx->olen = sha3_olen[type];
	ctx->dsep = sha3_dsep[type];

	return 0;
}

int mbedcrypto_sha3_update(struct mbedcrypto_sha3_ctx *ctx,
		const uint8_t *input, size_t ilen)
{
	size_t fill = 0;

	if (!ctx)
		return -EINVAL;
	if (ilen == 0)
		return 0;
	if (!input)
		return -EINVAL;

	/* Fill existing buffer first */
	if (ctx->bufsz > 0) {
		fill = ctx->rate - ctx->bufsz;
		if (ilen < fill) {
			memcpy(ctx->buf + ctx->bufsz, input, ilen);
			ctx->bufsz += ilen;
			return 0;
		}
		memcpy(ctx->buf + ctx->bufsz, input, fill);
		keccak_absorb(ctx->state, ctx->buf, ctx->rate);
		input += fill;
		ilen -= fill;
		ctx->bufsz = 0;
	}

	/* Process complete rate-blocks */
	while (ilen >= ctx->rate) {
		keccak_absorb(ctx->state, input, ctx->rate);
		input += ctx->rate;
		ilen -= ctx->rate;
	}

	/* Buffer remaining bytes */
	if (ilen > 0) {
		memcpy(ctx->buf, input, ilen);
		ctx->bufsz = ilen;
	}

	return 0;
}

int mbedcrypto_sha3_final(struct mbedcrypto_sha3_ctx *ctx,
		uint8_t *output, size_t olen)
{
	size_t i = 0, out_olen = 0;
	uint64_t lane = 0;

	if (!ctx || !output)
		return -EINVAL;

	/* For fixed-output SHA-3, enforce minimum olen */
	if (ctx->olen > 0) {
		if (olen < ctx->olen)
			return -ERANGE;
		out_olen = ctx->olen;
	} else {
		/* SHAKE XOF: caller specifies output length */
		out_olen = olen;
	}

	/*
	 * Padding: domain separator + pad10*1.
	 * SHA-3: 0x06, SHAKE: 0x1f
	 */
	memset(ctx->buf + ctx->bufsz, 0, ctx->rate - ctx->bufsz);
	ctx->buf[ctx->bufsz] = ctx->dsep;
	ctx->buf[ctx->rate - 1] |= 0x80;

	keccak_absorb(ctx->state, ctx->buf, ctx->rate);

	/* Squeeze: extract output, re-permuting if needed */
	for (i = 0; i < out_olen; ) {
		if (i > 0 && (i % ctx->rate) == 0)
			keccak_f1600(ctx->state);

		lane = ctx->state[(i % ctx->rate) / 8];
		if (out_olen - i >= 8) {
			memcpy(output + i, &lane, 8);
			i += 8;
		} else {
			memcpy(output + i, &lane, out_olen - i);
			i = out_olen;
		}
	}

	return 0;
}

void mbedcrypto_sha3_clone(struct mbedcrypto_sha3_ctx *dst,
		const struct mbedcrypto_sha3_ctx *src)
{
	if (dst && src)
		*dst = *src;
}

void mbedcrypto_sha3_cleanup(struct mbedcrypto_sha3_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}
