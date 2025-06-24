// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * MD5 implementation (RFC 1321)
 *
 * WARNING: MD5 is cryptographically broken.
 * Provided only for legacy compatibility.
 */

#include <string.h>

#include <mbedcrypto/md5.h>

/* MD5 boolean functions (optimized forms) */
#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

/* Per-round sine-derived constants T[i] = floor(2^32 * |sin(i+1)|) (RFC 1321) */
static const uint32_t md5_T[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

/*
 * Single MD5 step: add boolean function result, message word, and
 * sine constant; rotate and accumulate. Variable permutation at call site.
 */
#define P(a, b, c, d, fn, k, s, t) do { \
	(a) += fn((b), (c), (d)) + m[(k)] + (t); \
	(a) = (b) + mbedcrypto_rotl32((a), (s)); \
} while (0)

/*
 * Process one 64-byte block through the MD5 compression function.
 *
 * 4x unrolled loops (matching the 4-variable rotation period) with
 * table-driven sine constants. Balances code size and performance
 * for this legacy algorithm.
 */
static void md5_compress(uint32_t h[4], const uint8_t block[64])
{
	uint32_t m[16];
	uint32_t a, b, c, d;
	int i;

	for (i = 0; i < 16; i++)
		m[i] = mbedcrypto_get_le32(block + 4 * i);

	a = h[0]; b = h[1]; c = h[2]; d = h[3];

	/* Round 1: F function, word index = i */
	for (i = 0; i < 16; i += 4) {
		P(a, b, c, d, F, i,      7, md5_T[i]);
		P(d, a, b, c, F, i + 1, 12, md5_T[i + 1]);
		P(c, d, a, b, F, i + 2, 17, md5_T[i + 2]);
		P(b, c, d, a, F, i + 3, 22, md5_T[i + 3]);
	}
	/* Round 2: G function, word index = (5i+1) mod 16 */
	for (; i < 32; i += 4) {
		P(a, b, c, d, G, (5 * i + 1) & 0xf,       5, md5_T[i]);
		P(d, a, b, c, G, (5 * (i+1) + 1) & 0xf,   9, md5_T[i + 1]);
		P(c, d, a, b, G, (5 * (i+2) + 1) & 0xf,  14, md5_T[i + 2]);
		P(b, c, d, a, G, (5 * (i+3) + 1) & 0xf,  20, md5_T[i + 3]);
	}
	/* Round 3: H function, word index = (3i+5) mod 16 */
	for (; i < 48; i += 4) {
		P(a, b, c, d, H, (3 * i + 5) & 0xf,       4, md5_T[i]);
		P(d, a, b, c, H, (3 * (i+1) + 5) & 0xf,  11, md5_T[i + 1]);
		P(c, d, a, b, H, (3 * (i+2) + 5) & 0xf,  16, md5_T[i + 2]);
		P(b, c, d, a, H, (3 * (i+3) + 5) & 0xf,  23, md5_T[i + 3]);
	}
	/* Round 4: I function, word index = 7i mod 16 */
	for (; i < 64; i += 4) {
		P(a, b, c, d, I, (7 * i) & 0xf,       6, md5_T[i]);
		P(d, a, b, c, I, (7 * (i+1)) & 0xf,  10, md5_T[i + 1]);
		P(c, d, a, b, I, (7 * (i+2)) & 0xf,  15, md5_T[i + 2]);
		P(b, c, d, a, I, (7 * (i+3)) & 0xf,  21, md5_T[i + 3]);
	}

	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
}

int mbedcrypto_md5_init(struct mbedcrypto_md5_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	/* MD5 initial hash values (RFC 1321 Section 3.3) */
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;

	return 0;
}

int mbedcrypto_md5_update(struct mbedcrypto_md5_ctx *ctx,
		const uint8_t *data, size_t len)
{
	size_t buffered, space;

	if (!ctx)
		return -EINVAL;
	if (len == 0)
		return 0;
	if (!data)
		return -EINVAL;

	buffered = ctx->count & 0x3f;
	ctx->count += len;

	if (buffered > 0) {
		space = MBEDCRYPTO_MD5_BLKSIZE - buffered;
		if (len < space) {
			memcpy(ctx->blk + buffered, data, len);
			return 0;
		}
		memcpy(ctx->blk + buffered, data, space);
		md5_compress(ctx->h, ctx->blk);
		data += space;
		len -= space;
	}

	while (len >= MBEDCRYPTO_MD5_BLKSIZE) {
		md5_compress(ctx->h, data);
		data += MBEDCRYPTO_MD5_BLKSIZE;
		len -= MBEDCRYPTO_MD5_BLKSIZE;
	}

	if (len > 0)
		memcpy(ctx->blk, data, len);

	return 0;
}

int mbedcrypto_md5_final(struct mbedcrypto_md5_ctx *ctx, uint8_t *out)
{
	size_t buffered = 0;
	uint64_t bits = 0;
	int i;

	if (!ctx || !out)
		return -EINVAL;

	buffered = ctx->count & 0x3f;
	bits = ctx->count << 3;

	ctx->blk[buffered++] = 0x80;

	if (buffered > 56) {
		memset(ctx->blk + buffered, 0, MBEDCRYPTO_MD5_BLKSIZE - buffered);
		md5_compress(ctx->h, ctx->blk);
		buffered = 0;
	}

	memset(ctx->blk + buffered, 0, 56 - buffered);
	/* MD5 uses little-endian bit count */
	mbedcrypto_put_le64(ctx->blk + 56, bits);
	md5_compress(ctx->h, ctx->blk);

	for (i = 0; i < 4; i++)
		mbedcrypto_put_le32(out + 4 * i, ctx->h[i]);

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

void mbedcrypto_md5_clone(struct mbedcrypto_md5_ctx *dst,
		const struct mbedcrypto_md5_ctx *src)
{
	if (dst && src)
		memcpy(dst, src, sizeof(*dst));
}

void mbedcrypto_md5_cleanup(struct mbedcrypto_md5_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_md5_digest(const uint8_t *data, size_t len, uint8_t *out)
{
	struct mbedcrypto_md5_ctx ctx;
	int ret = 0;

	ret = mbedcrypto_md5_init(&ctx);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_md5_update(&ctx, data, len);
	if (ret != 0)
		goto done;

	ret = mbedcrypto_md5_final(&ctx, out);

done:
	memset(&ctx, 0, sizeof(ctx));
	return ret;
}
