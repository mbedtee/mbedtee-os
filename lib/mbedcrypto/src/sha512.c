// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SHA-512 and SHA-384 implementation (FIPS 180-4)
 */

#include <string.h>

#include <mbedcrypto/sha512.h>

/*
 * SHA-512 round constants (first 64 bits of the fractional
 * parts of the cube roots of the first 80 primes 2..409)
 */
static const uint64_t rc[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

/* SHA-512 logical functions (FIPS 180-4 Section 4.1.3) */
#define CH(x, y, z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)       (mbedcrypto_rotr64(x, 28) ^ mbedcrypto_rotr64(x, 34) ^ mbedcrypto_rotr64(x, 39))
#define BSIG1(x)       (mbedcrypto_rotr64(x, 14) ^ mbedcrypto_rotr64(x, 18) ^ mbedcrypto_rotr64(x, 41))
#define SSIG0(x)       (mbedcrypto_rotr64(x, 1) ^ mbedcrypto_rotr64(x, 8) ^ ((x) >> 7))
#define SSIG1(x)       (mbedcrypto_rotr64(x, 19) ^ mbedcrypto_rotr64(x, 61) ^ ((x) >> 6))

/* Message schedule: circular buffer with on-the-fly expansion */
#define WW(t)      w[(t) & 0x0f]
#define SCHED(t)   (WW(t) = SSIG1(WW((t) - 2)) + WW((t) - 7) + \
                    SSIG0(WW((t) - 15)) + WW((t) - 16))

/*
 * Process one 128-byte block through the SHA-512 compression function.
 *
 * Uses a 16-word circular message schedule (128 bytes) instead of
 * the full 80-word expansion (640 bytes), saving 512 bytes of stack.
 */
static void sha512_compress(uint64_t h[8], const uint8_t block[128])
{
	uint64_t w[16];
	uint64_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, hh = 0;
	uint64_t t1 = 0, t2 = 0;
	int i = 0;

	for (i = 0; i < 16; i++)
		w[i] = mbedcrypto_get_be64(block + 8 * i);

	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];

	/* Rounds 0-15: use pre-loaded message words */
	for (i = 0; i < 16; i++) {
		t1 = hh + BSIG1(e) + CH(e, f, g) + rc[i] + WW(i);
		t2 = BSIG0(a) + MAJ(a, b, c);
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	/* Rounds 16-79: expand on-the-fly */
	for (; i < 80; i++) {
		t1 = hh + BSIG1(e) + CH(e, f, g) + rc[i] + SCHED(i);
		t2 = BSIG0(a) + MAJ(a, b, c);
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

int mbedcrypto_sha512_init(struct mbedcrypto_sha512_ctx *ctx, int variant)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->is384 = variant;

	if (variant) {
		/* SHA-384 initial hash values (FIPS 180-4 Section 5.3.4) */
		ctx->h[0] = 0xcbbb9d5dc1059ed8ULL;
		ctx->h[1] = 0x629a292a367cd507ULL;
		ctx->h[2] = 0x9159015a3070dd17ULL;
		ctx->h[3] = 0x152fecd8f70e5939ULL;
		ctx->h[4] = 0x67332667ffc00b31ULL;
		ctx->h[5] = 0x8eb44a8768581511ULL;
		ctx->h[6] = 0xdb0c2e0d64f98fa7ULL;
		ctx->h[7] = 0x47b5481dbefa4fa4ULL;
	} else {
		/* SHA-512 initial hash values (FIPS 180-4 Section 5.3.5) */
		ctx->h[0] = 0x6a09e667f3bcc908ULL;
		ctx->h[1] = 0xbb67ae8584caa73bULL;
		ctx->h[2] = 0x3c6ef372fe94f82bULL;
		ctx->h[3] = 0xa54ff53a5f1d36f1ULL;
		ctx->h[4] = 0x510e527fade682d1ULL;
		ctx->h[5] = 0x9b05688c2b3e6c1fULL;
		ctx->h[6] = 0x1f83d9abfb41bd6bULL;
		ctx->h[7] = 0x5be0cd19137e2179ULL;
	}

	return 0;
}

int mbedcrypto_sha512_update(struct mbedcrypto_sha512_ctx *ctx,
		const uint8_t *data, size_t len)
{
	size_t buffered = 0, space = 0;

	if (!ctx)
		return -EINVAL;
	if (len == 0)
		return 0;
	if (!data)
		return -EINVAL;

	buffered = ctx->count[0] & 0x7f;

	/* Update 128-bit byte counter */
	ctx->count[0] += len;
	if (ctx->count[0] < (uint64_t)len)
		ctx->count[1]++;

	if (buffered > 0) {
		space = MBEDCRYPTO_SHA512_BLKSIZE - buffered;
		if (len < space) {
			memcpy(ctx->blk + buffered, data, len);
			return 0;
		}
		memcpy(ctx->blk + buffered, data, space);
		sha512_compress(ctx->h, ctx->blk);
		data += space;
		len -= space;
	}

	while (len >= MBEDCRYPTO_SHA512_BLKSIZE) {
		sha512_compress(ctx->h, data);
		data += MBEDCRYPTO_SHA512_BLKSIZE;
		len -= MBEDCRYPTO_SHA512_BLKSIZE;
	}

	if (len > 0)
		memcpy(ctx->blk, data, len);

	return 0;
}

int mbedcrypto_sha512_final(struct mbedcrypto_sha512_ctx *ctx, uint8_t *out)
{
	size_t buffered = 0;
	uint64_t bits_hi = 0, bits_lo = 0;
	int i = 0, hashwords = 0;

	if (!ctx || !out)
		return -EINVAL;

	buffered = ctx->count[0] & 0x7f;
	bits_lo = ctx->count[0] << 3;
	bits_hi = (ctx->count[1] << 3) | (ctx->count[0] >> 61);

	/* Padding: append 1 bit, then zeros, then 128-bit big-endian bit count */
	ctx->blk[buffered++] = 0x80;

	if (buffered > 112) {
		memset(ctx->blk + buffered, 0, MBEDCRYPTO_SHA512_BLKSIZE - buffered);
		sha512_compress(ctx->h, ctx->blk);
		buffered = 0;
	}

	memset(ctx->blk + buffered, 0, 112 - buffered);
	mbedcrypto_put_be64(ctx->blk + 112, bits_hi);
	mbedcrypto_put_be64(ctx->blk + 120, bits_lo);
	sha512_compress(ctx->h, ctx->blk);

	/* SHA-384 outputs first 6 words, SHA-512 outputs all 8 */
	hashwords = ctx->is384 ? 6 : 8;
	for (i = 0; i < hashwords; i++)
		mbedcrypto_put_be64(out + 8 * i, ctx->h[i]);

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

void mbedcrypto_sha512_clone(struct mbedcrypto_sha512_ctx *dst,
		const struct mbedcrypto_sha512_ctx *src)
{
	if (dst && src)
		memcpy(dst, src, sizeof(*dst));
}

void mbedcrypto_sha512_cleanup(struct mbedcrypto_sha512_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_sha512_digest(const uint8_t *data, size_t len,
		uint8_t *out, int variant)
{
	struct mbedcrypto_sha512_ctx ctx;
	int ret = 0;

	ret = mbedcrypto_sha512_init(&ctx, variant);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_sha512_update(&ctx, data, len);
	if (ret != 0)
		goto done;

	ret = mbedcrypto_sha512_final(&ctx, out);

done:
	memset(&ctx, 0, sizeof(ctx));
	return ret;
}
