// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Ed448 / X448 (RFC 8032, RFC 7748)
 *
 * Field arithmetic over GF(2^448-2^224-1) (Goldilocks prime).
 * Uses 16 digits of 28 bits each. Montgomery ladder for X448,
 * extended coordinates for Ed448. SHAKE256 based signing per
 * RFC 8032.
 */

#include <string.h>
#include <errno.h>

#include <mbedcrypto/curve448.h>
#include <mbedcrypto/sha3.h>
#include <mbedcrypto/types.h>

/* ---------------------------------------------------------------- */
/* Field element: 16 digits of 28 bits each (448 bits total)        */
/* p = 2^448 - 2^224 - 1                                           */
/* ---------------------------------------------------------------- */

#define NDIGITS 16
#define LBITS  28
#define LMASK  ((uint32_t)((1U << LBITS) - 1))

typedef uint32_t gf[NDIGITS];

static void gf_0(gf h)
{
	memset(h, 0, NDIGITS * sizeof(uint32_t));
}

static void gf_1(gf h)
{
	h[0] = 1;
	memset(h + 1, 0, (NDIGITS - 1) * sizeof(uint32_t));
}

static void gf_copy(gf h, const gf f)
{
	memcpy(h, f, NDIGITS * sizeof(uint32_t));
}

/* Load 56 bytes (little-endian) into a field element */
static void gf_deserialize(gf h, const uint8_t *s)
{
	int i = 0;

	for (i = 0; i < NDIGITS; i++) {
		int bit_off = i * LBITS;
		int byte_off = bit_off / 8;
		int shift = bit_off % 8;
		uint64_t v = 0;

		/* Read up to 5 bytes starting at byte_off */
		v = (uint64_t)s[byte_off];
		if (byte_off + 1 < 56) v |= (uint64_t)s[byte_off + 1] << 8;
		if (byte_off + 2 < 56) v |= (uint64_t)s[byte_off + 2] << 16;
		if (byte_off + 3 < 56) v |= (uint64_t)s[byte_off + 3] << 24;
		if (byte_off + 4 < 56) v |= (uint64_t)s[byte_off + 4] << 32;

		h[i] = v >> shift & LMASK;
	}
}

/* Serialize field element to 56 bytes (little-endian, reduced mod p) */
static void gf_serialize(uint8_t *s, const gf h)
{
	int i = 0;
	gf t;

	gf_copy(t, h);

	/* Weak reduction - carry chain */
	for (i = 0; i < NDIGITS - 1; i++) {
		t[i + 1] += t[i] >> LBITS;
		t[i] &= LMASK;
	}
	/* Reduce top: t[15] overflow goes to t[0] and t[8] (mod p) */
	{
		uint32_t c = t[NDIGITS - 1] >> LBITS;

		t[NDIGITS - 1] &= LMASK;
		t[0] += c;
		t[8] += c;
	}
	/* One more carry pass */
	for (i = 0; i < NDIGITS - 1; i++) {
		t[i + 1] += t[i] >> LBITS;
		t[i] &= LMASK;
	}

	/*
	 * Full reduction: if t >= p, subtract p.
	 * p = 2^448 - 2^224 - 1, so t >= p iff t + 1 + 2^224 >= 2^448
	 */
	{
		gf u;
		uint32_t carry = 1;
		uint32_t mask = 0;

		for (i = 0; i < NDIGITS; i++)
			u[i] = t[i];

		/* Try to add 1 (since p+1 = 2^448 - 2^224) */
		u[0] += 1;
		u[8] += 1;  /* add 2^224 */

		for (i = 0; i < NDIGITS; i++)
			u[i] += (carry > 0 && i > 0) ? 0 : 0;
		/* Carry chain */
		for (i = 0; i < NDIGITS - 1; i++) {
			u[i + 1] += u[i] >> LBITS;
			u[i] &= LMASK;
		}
		/* Check if u[15] overflowed (>= 2^28) */
		mask = (uint32_t)(-(int32_t)(u[NDIGITS - 1] >> LBITS));

		/* If overflow, use reduced value (u mod 2^448 - what we added) */
		u[NDIGITS - 1] &= LMASK;
		for (i = 0; i < NDIGITS; i++)
			t[i] = (u[i] & mask) | (t[i] & ~mask);
	}

	memset(s, 0, 56);
	for (i = 0; i < NDIGITS; i++) {
		int bit_off = i * LBITS;
		int byte_off = bit_off / 8;
		int shift = bit_off % 8;
		uint64_t v = (uint64_t)t[i] << shift;
		int j = 0;

		for (j = 0; j < 5 && byte_off + j < 56; j++)
			s[byte_off + j] |= v >> (8 * j);
	}
}

/* h = f + g */
static void gf_add(gf h, const gf f, const gf g)
{
	int i = 0;

	for (i = 0; i < NDIGITS; i++)
		h[i] = f[i] + g[i];
}

/* h = f - g + 2p (to keep positive) */
static void gf_sub(gf h, const gf f, const gf g)
{
	int i = 0;
	uint32_t c = 0;
	/*
	 * Add 2*p to avoid underflow.
	 * p = 2^448 - 2^224 - 1
	 * In our 16-digit representation (28 bits each):
	 *   p = [LMASK, ..., LMASK, LMASK-1, LMASK, ..., LMASK]
	 *        digit0-7             digit8     digit9-15
	 * So 2p has digit 8 = 2*LMASK - 2, all others = 2*LMASK.
	 */
	static const uint32_t bias_lo = 2 * LMASK;
	static const uint32_t bias_hi = 2 * LMASK - 2;

	for (i = 0; i < NDIGITS; i++) {
		uint32_t bias = (i == 8) ? bias_hi : bias_lo;
		h[i] = f[i] + bias - g[i];
	}
	/* Carry to keep canonical */
	for (i = 0; i < NDIGITS - 1; i++) {
		h[i + 1] += h[i] >> LBITS;
		h[i] &= LMASK;
	}
	c = h[NDIGITS - 1] >> LBITS;

	h[NDIGITS - 1] &= LMASK;
	h[0] += c;
	h[8] += c;
}

/* h = f * g with Karatsuba using the Goldilocks structure */
static void gf_mul(gf h, const gf f, const gf g)
{
	uint64_t accum[NDIGITS] = {0};
	uint64_t c = 0;
	int i = 0, j = 0;

	/*
	 * Schoolbook multiplication with reduction mod p.
	 * p = 2^448 - 2^224 - 1 means:
	 * - Digits 0..7 are the "low" 224-bit part
	 * - Digits 8..15 are the "high" 224-bit part
	 * - When a product lands in digit >= 16, the
	 *   overflow wraps: 2^448 = 2^224 + 1 (mod p)
	 */
	for (i = 0; i < NDIGITS; i++) {
		for (j = 0; j < NDIGITS; j++) {
			uint64_t prod = (uint64_t)f[i] * g[j];
			int k = i + j;

			if (k < NDIGITS)
				accum[k] += prod;
			else {
				/* k >= 16: reduce. 2^448 = 2^224 + 1 mod p */
				int kk = k - NDIGITS;

				accum[kk] += prod;      /* += prod * 1 */

				if (kk + 8 < NDIGITS) {
					accum[kk + 8] += prod;  /* += prod * 2^224 */
				} else {
					/*
					 * kk+8 >= 16: second-level reduction.
					 * 2^{28*(kk+8)} with kk+8 >= 16:
					 * let kk2 = kk - 8, then
					 * = 2^{28*kk2} * 2^448
					 * = 2^{28*kk2} * (2^224 + 1)
					 * = 2^{28*(kk2+8)} + 2^{28*kk2}
					 * = 2^{28*kk}   + 2^{28*(kk-8)}
					 */
					accum[kk] += prod;      /* += prod * 2^{28*kk} */
					accum[kk - 8] += prod;  /* += prod * 2^{28*(kk-8)} */
				}
			}
		}
	}

	/* Carry chain */
	for (i = 0; i < NDIGITS - 1; i++) {
		accum[i + 1] += accum[i] >> LBITS;
		accum[i] &= LMASK;
	}
	c = accum[NDIGITS - 1] >> LBITS;
	accum[NDIGITS - 1] &= LMASK;
	accum[0] += c;
	accum[8] += c;

	/* One more carry pass */
	for (i = 0; i < NDIGITS - 1; i++) {
		accum[i + 1] += accum[i] >> LBITS;
		accum[i] &= LMASK;
	}
	c = accum[NDIGITS - 1] >> LBITS;
	accum[NDIGITS - 1] &= LMASK;
	accum[0] += c;
	accum[8] += c;

	for (i = 0; i < NDIGITS; i++)
		h[i] = accum[i];
}

static void gf_sq(gf h, const gf f)
{
	gf_mul(h, f, f);
}

static void gf_sq_n(gf h, const gf f, int n)
{
	gf_sq(h, f);
	while (--n > 0)
		gf_sq(h, h);
}

/*
 * h = 1/f (mod p), via Fermat: f^(p-2)
 *
 * p - 2 = 2^448 - 2^224 - 3
 * Binary (MSB first): {1^223}{0}{1^222}{01}
 *
 * Strategy: build f^(2^k-1) for various k using an addition chain,
 * then combine f^(2^223-1) and f^(2^222-1) via the bit pattern.
 */
static void gf_invert(gf h, const gf f)
{
	gf a3, a4m1, a7m1, a6m1;
	gf a13m1, a14m1, a28m1, a56m1, a112m1;
	gf a223m1;

	/* a3 = f^3 */
	gf_sq(a3, f);
	gf_mul(a3, a3, f);

	/* a4m1 = f^(2^4-1) = f^15 */
	gf_sq_n(a4m1, a3, 2);
	gf_mul(a4m1, a4m1, a3);

	/* a7m1 = f^(2^7-1) = f^127 */
	{
		gf f7;

		gf_sq(f7, a3);
		gf_mul(f7, f7, f);         /* f^7 */
		gf_sq_n(a7m1, a4m1, 3);    /* f^120 */
		gf_mul(a7m1, a7m1, f7);    /* f^127 */
	}

	/* a6m1 = f^(2^6-1) = f^63 */
	gf_sq_n(a6m1, a4m1, 2);
	gf_mul(a6m1, a6m1, a3);

	/* a13m1 = f^(2^13-1) */
	gf_sq_n(a13m1, a7m1, 6);
	gf_mul(a13m1, a13m1, a6m1);

	/* a14m1 = f^(2^14-1) */
	gf_sq(a14m1, a13m1);
	gf_mul(a14m1, a14m1, f);

	{
		gf a27m1, a55m1, a111m1;

		/* a27m1 = f^(2^27-1) */
		gf_sq_n(a27m1, a14m1, 13);
		gf_mul(a27m1, a27m1, a13m1);

		/* a28m1 = f^(2^28-1) */
		gf_sq(a28m1, a27m1);
		gf_mul(a28m1, a28m1, f);

		/* a55m1 = f^(2^55-1) */
		gf_sq_n(a55m1, a28m1, 27);
		gf_mul(a55m1, a55m1, a27m1);

		/* a56m1 = f^(2^56-1) */
		gf_sq(a56m1, a55m1);
		gf_mul(a56m1, a56m1, f);

		/* a111m1 = f^(2^111-1) */
		gf_sq_n(a111m1, a56m1, 55);
		gf_mul(a111m1, a111m1, a55m1);

		/* a112m1 = f^(2^112-1) */
		gf_sq(a112m1, a111m1);
		gf_mul(a112m1, a112m1, f);

		/* a223m1 = f^(2^223-1) */
		gf_sq_n(a223m1, a112m1, 111);
		gf_mul(a223m1, a223m1, a111m1);
	}

	/*
	 * Build f^(2^222-1) for the even-length run of ones.
	 * Then combine into f^(p-2).
	 */
	{
		gf a5m1, a12m1, a26m1, a54m1, a110m1, a222m1;
		gf f_orig;

		/* a5m1 = f^(2^5-1) = f^31 */
		gf_sq(a5m1, a4m1);
		gf_mul(a5m1, a5m1, f);

		/* a12m1 = f^(2^12-1) */
		gf_sq_n(a12m1, a7m1, 5);
		gf_mul(a12m1, a12m1, a5m1);

		/* a26m1 = f^(2^26-1) */
		gf_sq_n(a26m1, a14m1, 12);
		gf_mul(a26m1, a26m1, a12m1);

		/* a54m1 = f^(2^54-1) */
		gf_sq_n(a54m1, a28m1, 26);
		gf_mul(a54m1, a54m1, a26m1);

		/* a110m1 = f^(2^110-1) */
		gf_sq_n(a110m1, a56m1, 54);
		gf_mul(a110m1, a110m1, a54m1);

		/* a222m1 = f^(2^222-1) */
		gf_sq_n(a222m1, a112m1, 110);
		gf_mul(a222m1, a222m1, a110m1);

		/* Save f before writing h (h may alias f) */
		gf_copy(f_orig, f);

		/* f^(p-2) via the bit pattern {1^223}{0}{1^222}{01} */
		gf_copy(h, a223m1);    /* f^(2^223-1) */
		gf_sq(h, h);           /* f^(2^224-2)               [bit 224=0] */
		gf_sq_n(h, h, 222);   /* f^(2^446-2^223) */
		gf_mul(h, h, a222m1);  /* f^(2^446-2^222-1)         [bits 223..2] */
		gf_sq(h, h);           /* f^(2^447-2^223-2)         [bit 1=0] */
		gf_sq(h, h);           /* f^(2^448-2^224-4) */
		gf_mul(h, h, f_orig);  /* f^(2^448-2^224-3) = f^(p-2) [bit 0=1] */
	}
}

static void gf_neg(gf h, const gf f)
{
	/* h = p - f = (2^448-2^224-1) - f */
	/* Use 2p - f approach for safety */
	gf zero;

	gf_0(zero);
	gf_sub(h, zero, f);
}

/* Constant-time swap */
static void gf_cswap(gf f, gf g, int b)
{
	uint32_t mask = (uint32_t)(-(int32_t)b);
	uint32_t t = 0;
	int i = 0;

	for (i = 0; i < NDIGITS; i++) {
		t = mask & (f[i] ^ g[i]);
		f[i] ^= t;
		g[i] ^= t;
	}
}

/* h = 39081 * f (the a24 constant for X448) */
static void gf_mul39081(gf h, const gf f)
{
	uint64_t accum[NDIGITS];
	uint64_t c = 0;
	int i = 0;

	for (i = 0; i < NDIGITS; i++)
		accum[i] = (uint64_t)f[i] * 39081;

	for (i = 0; i < NDIGITS - 1; i++) {
		accum[i + 1] += accum[i] >> LBITS;
		accum[i] &= LMASK;
	}
	c = accum[NDIGITS - 1] >> LBITS;
	accum[NDIGITS - 1] &= LMASK;
	accum[0] += c;
	accum[8] += c;

	for (i = 0; i < NDIGITS - 1; i++) {
		accum[i + 1] += accum[i] >> LBITS;
		accum[i] &= LMASK;
	}

	for (i = 0; i < NDIGITS; i++)
		h[i] = accum[i];
}

/* ---------------------------------------------------------------- */
/* X448: Montgomery ladder scalar multiplication                    */
/* RFC 7748 Section 5                                                */
/* ---------------------------------------------------------------- */

/* X448 clamping */
static void x448_clamp(uint8_t e[56])
{
	e[0] &= 252;
	e[55] |= 128;
}

/*
 * Scalar multiplication on Montgomery curve y^2=x^3+Ax^2+x
 * where A=156326.  a24=(A-2)/4=39081.
 */
static void x448_scalar_mult(uint8_t out[56],
		const uint8_t scalar[56], const uint8_t point[56])
{
	gf x1, x2, z2, x3, z3, tmp0, tmp1;
	uint8_t e[56];
	int swap = 0, b, i;

	memcpy(e, scalar, 56);

	gf_deserialize(x1, point);
	gf_1(x2);
	gf_0(z2);
	gf_copy(x3, x1);
	gf_1(z3);

	for (i = 447; i >= 0; i--) {
		b = (e[i >> 3] >> (i & 7)) & 1;
		swap ^= b;
		gf_cswap(x2, x3, swap);
		gf_cswap(z2, z3, swap);
		swap = b;

		gf_sub(tmp0, x3, z3);       /* A = x3-z3 */
		gf_sub(tmp1, x2, z2);       /* B = x2-z2 */
		gf_add(x2, x2, z2);         /* C = x2+z2 */
		gf_add(z2, x3, z3);         /* D = x3+z3 */
		gf_mul(z3, tmp0, x2);       /* DA = A*C */
		gf_mul(z2, z2, tmp1);       /* CB = D*B */
		gf_sq(tmp0, tmp1);          /* BB = B^2 */
		gf_sq(tmp1, x2);            /* CC = C^2 */
		gf_add(x3, z3, z2);         /* DA+CB */
		gf_sub(z2, z3, z2);         /* DA-CB */
		gf_mul(x2, tmp1, tmp0);     /* x2 = CC*BB */
		gf_sub(tmp1, tmp1, tmp0);   /* E = CC-BB */
		gf_sq(z2, z2);              /* (DA-CB)^2 */
		gf_mul39081(z3, tmp1);      /* a24*E where a24=(A-2)/4=39081 */
		gf_sq(x3, x3);             /* (DA+CB)^2 */
		gf_add(tmp0, tmp0, z3);     /* BB+a24*E */
		gf_add(tmp0, tmp0, tmp1);   /* BB+(a24+1)*E = AA+a24*E */
		gf_mul(z3, x1, z2);        /* z3 = x1*(DA-CB)^2 */
		gf_mul(z2, tmp1, tmp0);     /* z2 = E*(AA+a24*E) */
	}

	gf_cswap(x2, x3, swap);
	gf_cswap(z2, z3, swap);

	gf_invert(z2, z2);
	gf_mul(x2, x2, z2);
	gf_serialize(out, x2);
}

/* The base point u=5 for X448 */
static const uint8_t x448_basepoint[56] = { 5 };

int mbedcrypto_x448_calc_public(
		uint8_t pub[MBEDCRYPTO_X448_KEY_SIZE],
		const uint8_t priv[MBEDCRYPTO_X448_KEY_SIZE])
{
	uint8_t e[56];

	if (!pub || !priv)
		return -EINVAL;

	memcpy(e, priv, 56);
	x448_clamp(e);
	x448_scalar_mult(pub, e, x448_basepoint);

	memset(e, 0, 56);
	return 0;
}

int mbedcrypto_x448_calc_secret(
		uint8_t secret[MBEDCRYPTO_X448_KEY_SIZE],
		const uint8_t our_priv[MBEDCRYPTO_X448_KEY_SIZE],
		const uint8_t their_pub[MBEDCRYPTO_X448_KEY_SIZE])
{
	uint8_t e[56];

	if (!secret || !our_priv || !their_pub)
		return -EINVAL;

	memcpy(e, our_priv, 56);
	x448_clamp(e);
	x448_scalar_mult(secret, e, their_pub);

	memset(e, 0, 56);
	return 0;
}

int mbedcrypto_x448_gen_keypair(
		uint8_t pub[MBEDCRYPTO_X448_KEY_SIZE],
		uint8_t priv[MBEDCRYPTO_X448_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;

	if (!pub || !priv || !f_rng)
		return -EINVAL;

	if ((ret = f_rng(p_rng, priv, 56)) != 0)
		return ret;

	return mbedcrypto_x448_calc_public(pub, priv);
}

/* ---------------------------------------------------------------- */
/* Ed448: Extended coordinates (X:Y:Z:T) on                         */
/* Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2                      */
/* d = -39081                                                        */
/* ---------------------------------------------------------------- */

/* d = -39081 mod p, pre-deserialized into 28-bit words */
static const gf ed448_d = {
	0xfff6756, 0xfffffff, 0xfffffff, 0xfffffff,
	0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
	0xffffffe, 0xfffffff, 0xfffffff, 0xfffffff,
	0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
};

/* Ed448 base point Y coordinate (RFC 8032, converted to LE) */
static const uint8_t ed448_by_bytes[56] = {
	0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
	0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
	0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
	0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
	0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
	0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
	0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
};

/* Ed448 base point X coordinate (even root, derived from Y) */
static const uint8_t ed448_bx_bytes[56] = {
	0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26,
	0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43,
	0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12,
	0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea,
	0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e,
	0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
	0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f,
};

struct ge448_p3 {
	gf X, Y, Z, T;
};

static void ge448_p3_0(struct ge448_p3 *h)
{
	gf_0(h->X);
	gf_1(h->Y);
	gf_1(h->Z);
	gf_0(h->T);
}

/* Point doubling on Ed448-Goldilocks (x^2+y^2=1+d*x^2*y^2, a=1) */
static void ge448_dbl(struct ge448_p3 *r, const struct ge448_p3 *p)
{
	gf A, B, C, E, F, G, H;

	gf_sq(A, p->X);         /* A = X^2 */
	gf_sq(B, p->Y);         /* B = Y^2 */
	gf_sq(C, p->Z);         /* C = Z^2 */
	gf_add(C, C, C);        /* C = 2*Z^2 */
	/* D = a*A = A (since a=1 for Ed448), so use A directly */
	gf_add(E, p->X, p->Y);
	gf_sq(E, E);
	gf_sub(E, E, A);
	gf_sub(E, E, B);       /* E = (X+Y)^2-A-B */
	gf_add(G, A, B);       /* G = A+B (D=A since a=1) */
	gf_sub(F, G, C);       /* F = G-C */
	gf_sub(H, A, B);       /* H = A-B (D=A since a=1) */
	gf_mul(r->X, E, F);    /* r.X = E*F */
	gf_mul(r->Y, G, H);    /* r.Y = G*H */
	gf_mul(r->T, E, H);    /* r.T = E*H */
	gf_mul(r->Z, F, G);    /* r.Z = F*G */
}

/* Point addition on Ed448-Goldilocks */
static void ge448_add(struct ge448_p3 *r, const struct ge448_p3 *p, const struct ge448_p3 *q)
{
	gf A, B, C, D, E, F, G, H;

	gf_mul(A, p->X, q->X);  /* A = X1*X2 */
	gf_mul(B, p->Y, q->Y);  /* B = Y1*Y2 */
	gf_mul(C, p->T, q->T);
	gf_mul(C, C, ed448_d);  /* C = d*T1*T2 */
	gf_mul(D, p->Z, q->Z);  /* D = Z1*Z2 */

	gf_add(E, p->X, p->Y);
	gf_add(F, q->X, q->Y);
	gf_mul(E, E, F);
	gf_sub(E, E, A);
	gf_sub(E, E, B);       /* E = (X1+Y1)*(X2+Y2)-A-B */

	gf_sub(F, D, C);       /* F = D-C */
	gf_add(G, D, C);       /* G = D+C */
	gf_sub(H, B, A);       /* H = B - a*A = B - A (since a=1) */

	gf_mul(r->X, E, F);    /* r.X = E*F */
	gf_mul(r->Y, G, H);    /* r.Y = G*H */
	gf_mul(r->T, E, H);    /* r.T = E*H */
	gf_mul(r->Z, F, G);    /* r.Z = F*G */
}

/* Point subtraction */
static __attribute__((noinline)) void ge448_sub(struct ge448_p3 *r,
		const struct ge448_p3 *p, const struct ge448_p3 *q)
{
	struct ge448_p3 neg_q;

	gf_neg(neg_q.X, q->X);
	gf_copy(neg_q.Y, q->Y);
	gf_copy(neg_q.Z, q->Z);
	gf_neg(neg_q.T, q->T);

	ge448_add(r, p, &neg_q);
}

/* Compress a point to 57 bytes (RFC 8032 Section 5.2.2) */
static __attribute__((noinline)) void ge448_tobytes(uint8_t *s,
		const struct ge448_p3 *h)
{
	gf recip, x, y;

	gf_invert(recip, h->Z);
	gf_mul(x, h->X, recip);
	gf_mul(y, h->Y, recip);
	gf_serialize(s, y);
	/* RFC 8032: sign bit of x in bit 7 of byte 56 (bit 455) */
	{
		uint8_t xb[56];

		gf_serialize(xb, x);
		s[56] = (xb[0] & 1) << 7;
	}
}

/* Decompress from 57 bytes */
static __attribute__((noinline)) int ge448_frombytes(struct ge448_p3 *h,
		const uint8_t *s)
{
	gf u, v, candidate, check;
	int sign = 0;

	sign = (s[56] >> 7) & 1;

	/* y from first 56 bytes */
	gf_deserialize(h->Y, s);
	gf_1(h->Z);

	/*
	 * Ed448: x^2 + y^2 = 1 + d*x^2*y^2  (a=1)
	 * x^2 = (y^2 - 1) / (d*y^2 - 1)
	 * u = y^2 - 1, v = d*y^2 - 1
	 */
	gf_sq(u, h->Y);
	gf_mul(v, u, ed448_d);
	gf_sub(u, u, h->Z);   /* u = y^2 - 1 */
	gf_sub(v, v, h->Z);   /* v = d*y^2 - 1 */

	/* x = (u/v)^((p+1)/4) for p=3 mod 4 */
	/* For Goldilocks: p+1 = 2^448-2^224, (p+1)/4 = 2^446-2^222 */
	/*
	 * x = u^3 * v * (u^5 * v^3)^((p-3)/4) ... or simpler:
	 * Let w = u*v, then x = w^((p+1)/4) * u / w = ...
	 *
	 * Actually use: x = (u/v)^((p+1)/4)
	 * = u^((p+1)/4) * v^(-(p+1)/4)
	 * = u^((p+1)/4) * v^(p-1-(p+1)/4) = u^((p+1)/4) * v^((3p-5)/4)
	 * This is getting complex.
	 *
	 * Simpler: compute u*v^(p-2) = u/v, then take square root.
	 * sqrt(w) = w^((p+1)/4) since p = 3 mod 4.
	 */
	{
		gf w, vinv;

		gf_invert(vinv, v);
		gf_mul(w, u, vinv);   /* w = u/v = x^2 */

		/* sqrt(w) = w^((p+1)/4) */
		/* (p+1)/4 = (2^448-2^224)/4 = 2^446-2^222 */
		/*
		 * This is: bits 446=1, and bit 222=0
		 * More precisely: 2^446 - 2^222
		 * In binary: 1{223 zeros}{1}{221 zeros}... no.
		 * 2^446 - 2^222:
		 * bit 446 = 1
		 * bits 445..223 = 1 (all ones, 223 bits)
		 * bit 222 = 0
		 * bits 221..0 = 0
		 * Wait: 2^446 = 10..0 (446 zeros), subtract 2^222 = ...010..0 (222 zeros)
		 * 2^446 - 2^222 = 11..10..0 where we have (446-223)=223 ones, then 0, then 222 zeros
		 * Actually: 2^446 - 1 = 445 ones. 2^446 - 2^222 = 2^446 - 2^222.
		 * In binary (447 bits):
		 * 1{0^223}{0^223} = 2^446
		 * Subtract 2^222: bit 222 borrows...
		 * Result: 0{1^223}{0^222}... hmm let me think byte by byte.
		 * 2^446 = bit446=1, rest=0.
		 * -2^222: need to borrow from bit446.
		 * Result: bit446=0, bits445..223 all 1, bit222=0, bits221..0=0
		 * = bits 445..223 all 1 (223 bits), others 0.
		 * = 2^446-2^222 = sum of 2^k for k=223..445.
		 *
		 * Equivalently: (2^223-1)*2^223
		 *
		 * So w^((p+1)/4) = (w^(2^223-1))^(2^223)
		 * = w^(2^223-1) squared 223 times.
		 *
		 * We can compute w^(2^223-1) using the same chain as in gf_invert.
		 */
		{
			gf r2, r3, r4m1, r7m1, r14m1, r28m1, r56m1, r112m1;
			gf r6m1, r13m1, r27m1, r55m1, r111m1, r223m1;

			gf_sq(r2, w);
			gf_mul(r3, r2, w);
			gf_sq_n(r4m1, r3, 2);
			gf_mul(r4m1, r4m1, r3);
			gf_sq_n(r7m1, r4m1, 3);  /* w^(15*8) = w^120 */
			{
				gf w7;
				gf_sq(w7, r3);       /* w^6 */
				gf_mul(w7, w7, w);   /* w^7 = w^(2^3-1) */
				gf_mul(r7m1, r7m1, w7); /* w^127 = w^(2^7-1) */
			}
			gf_sq_n(r6m1, r4m1, 2);
			gf_mul(r6m1, r6m1, r3);
			gf_sq_n(r13m1, r7m1, 6);
			gf_mul(r13m1, r13m1, r6m1);
			gf_sq(r14m1, r13m1);
			gf_mul(r14m1, r14m1, w);
			gf_sq_n(r27m1, r14m1, 13);
			gf_mul(r27m1, r27m1, r13m1);
			gf_sq(r28m1, r27m1);
			gf_mul(r28m1, r28m1, w);
			gf_sq_n(r55m1, r28m1, 27);
			gf_mul(r55m1, r55m1, r27m1);
			gf_sq(r56m1, r55m1);
			gf_mul(r56m1, r56m1, w);
			gf_sq_n(r111m1, r56m1, 55);
			gf_mul(r111m1, r111m1, r55m1);
			gf_sq(r112m1, r111m1);
			gf_mul(r112m1, r112m1, w);
			gf_sq_n(r223m1, r112m1, 111);
			gf_mul(r223m1, r223m1, r111m1);

			/*
			 * (p+1)/4 = 2^446 - 2^222 = (2^224-1) * 2^222
			 * w^(2^224-1) = r223m1^2 * w
			 * candidate = (w^(2^224-1))^(2^222)
			 */
			gf_sq(candidate, r223m1);       /* w^(2^224-2) */
			gf_mul(candidate, candidate, w); /* w^(2^224-1) */
			gf_sq_n(candidate, candidate, 222);
		}

		/* Verify: candidate^2 == w ? */
		gf_sq(check, candidate);
		{
			uint8_t cb[56], wb[56];

			gf_serialize(cb, check);
			gf_serialize(wb, w);
			if (mbedcrypto_ct_memcmp(cb, wb, 56) != 0)
				return -EINVAL;
		}

		gf_copy(h->X, candidate);
	}

	/* Adjust sign */
	{
		uint8_t xb[56];

		gf_serialize(xb, h->X);
		if ((xb[0] & 1) != sign)
			gf_neg(h->X, h->X);
	}

	gf_mul(h->T, h->X, h->Y);
	return 0;
}

/* Scalar multiplication: r = [a]*P (double-and-add) */
static __attribute__((noinline)) void ge448_scalarmult(struct ge448_p3 *r,
		const uint8_t *a, size_t a_len, const struct ge448_p3 *p)
{
	int i = 0, b = 0;

	ge448_p3_0(r);

	for (i = (int)(a_len * 8) - 1; i >= 0; i--) {
		ge448_dbl(r, r);
		b = (a[i >> 3] >> (i & 7)) & 1;
		if (b) {
			struct ge448_p3 tmp;

			ge448_add(&tmp, r, p);
			*r = tmp;
		}
	}
}

/* Scalar multiplication with base point: r = [a]*B */
static __attribute__((noinline)) void ge448_scalarmult_base(struct ge448_p3 *r,
		const uint8_t *a, size_t a_len)
{
	struct ge448_p3 bp;

	gf_deserialize(bp.X, ed448_bx_bytes);
	gf_deserialize(bp.Y, ed448_by_bytes);
	gf_1(bp.Z);
	gf_mul(bp.T, bp.X, bp.Y);

	ge448_scalarmult(r, a, a_len, &bp);
}

/* ---------------------------------------------------------------- */
/* SHAKE256 helper                                                   */
/* ---------------------------------------------------------------- */

static void shake256(uint8_t *out, size_t olen,
		const uint8_t *in, size_t ilen)
{
	struct mbedcrypto_sha3_ctx ctx;

	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHAKE256);
	mbedcrypto_sha3_update(&ctx, in, ilen);
	mbedcrypto_sha3_final(&ctx, out, olen);
	mbedcrypto_sha3_cleanup(&ctx);
}

/* Multi-part SHAKE256: dom4 prefix + data segments */
/* Ed448 uses: SHAKE256(dom4(F,C) || x, ..., 114 bytes) */

/*
 * dom4(F,C) = "SigEd448" || octet(F) || octet(CLEN) || C
 * For pure Ed448: F=0, C="" (empty), CLEN=0
 * So dom4 = "SigEd448\x00\x00"
 */
static const uint8_t dom4_prefix[] = {
	'S','i','g','E','d','4','4','8', 0x00, 0x00
};

/*
 * Reduce a 114-byte SHAKE256 output mod the Ed448 group order L.
 *
 * L = 2^446 - 13818066809895115352007386748515426880336692
 *     47478731085248686798554486662655978309570655441479
 *
 * This is a 446-bit prime. We reduce a 912-bit number mod L.
 *
 * For simplicity, we use Barrett-like reduction by processing
 * the number in a big-integer representation and reducing mod L.
 *
 * Implementation: use a simplified approach - represent as bytes,
 * do repeated subtraction isn't practical for 114 bytes.
 *
 * Instead, we implement a proper modular reduction using the
 * Ed448 scalar arithmetic from RFC 8032.
 */

/*
 * Ed448 group order L (57 bytes, little-endian) packed as uint32_t words.
 *
 * L = 2^446 - 13818066809895115352007386748515426880336692474787310852486
 *     6798554486662655978309570655441479
 *
 * From RFC 8032:
 * L = 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
 *     7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3
 */
static const uint32_t ed448_Lw[15] = {
	0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272,
	0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
	0xffffffff, 0x3fffffff, 0x00000000
};

/*
 * Word-level mod L reduction for up to 114-byte LE integers.
 * Processes input bits MSB-to-LSB, maintaining a word-level
 * running remainder. Each inner loop operates on 15 uint32_t
 * words instead of 57 bytes.
 */
static void sc448_reduce(uint8_t out[57], const uint8_t *in, size_t in_len)
{
	uint32_t nw[29]; /* input in words (114 bytes max) */
	uint32_t r[16];  /* remainder: 15 words + carry */
	int i = 0, j = 0, bit = 0, ge = 0;
	size_t len = in_len < 114 ? in_len : 114;

	memset(nw, 0, sizeof(nw));
	for (i = 0; i < len; i++)
		nw[i >> 2] |= (uint32_t)in[i] << ((i & 3) * 8);

	memset(r, 0, sizeof(r));

	for (i = (int)len * 8 - 1; i >= 0; i--) {
		/* r = 2*r (word-level shift left by 1) */
		uint32_t carry = 0;

		for (j = 0; j < 15; j++) {
			uint32_t v = r[j];

			r[j] = (v << 1) | carry;
			carry = v >> 31;
		}
		r[15] = carry;

		/* r += input bit */
		bit = (nw[i >> 5] >> (i & 31)) & 1;
		if (bit) {
			uint64_t c = (uint64_t)r[0] + 1;

			r[0] = c;
			for (j = 1; j < 16 && (c >> 32); j++) {
				c = (uint64_t)r[j] + 1;
				r[j] = c;
			}
		}

		/* if r >= L: r -= L */
		if (r[15] > 0)
			ge = 1;
		else {
			ge = 0;
			for (j = 14; j >= 0; j--) {
				if (r[j] > ed448_Lw[j]) { ge = 1; break; }
				if (r[j] < ed448_Lw[j]) { ge = 0; break; }
			}
			if (j < 0) ge = 1; /* equal */
		}

		if (ge) {
			uint64_t borrow = 0;

			for (j = 0; j < 15; j++) {
				uint64_t v = (uint64_t)r[j] - ed448_Lw[j] - borrow;

				r[j] = v;
				borrow = v >> 63;
			}
			r[15] = 0;
		}
	}

	/* Unpack words to bytes */
	for (i = 0; i < 14; i++) {
		out[4 * i]     = r[i];
		out[4 * i + 1] = r[i] >> 8;
		out[4 * i + 2] = r[i] >> 16;
		out[4 * i + 3] = r[i] >> 24;
	}
	out[56] = r[14];
}

/*
 * sc448_muladd: compute s = (a*b + c) mod L
 * Uses word-level (uint32_t) schoolbook multiplication:
 * 15x15 = 225 word multiplies instead of 57x57 = 3249 byte multiplies.
 */
static void sc448_muladd(uint8_t s[57],
		const uint8_t a[57], const uint8_t b[57], const uint8_t c[57])
{
	uint32_t aw[15], bw[15], pw[30];
	int i = 0, j = 0;
	uint64_t carry = 0;

	/* Pack a and b into words */
	memset(aw, 0, sizeof(aw));
	memset(bw, 0, sizeof(bw));
	for (i = 0; i < 57; i++) {
		aw[i >> 2] |= (uint32_t)a[i] << ((i & 3) * 8);
		bw[i >> 2] |= (uint32_t)b[i] << ((i & 3) * 8);
	}

	/* Word-level schoolbook multiply: pw = aw * bw */
	memset(pw, 0, sizeof(pw));
	for (i = 0; i < 15; i++) {
		carry = 0;
		for (j = 0; j < 15; j++) {
			uint64_t v = (uint64_t)pw[i + j] +
			             (uint64_t)aw[i] * bw[j] + carry;

			pw[i + j] = v;
			carry = v >> 32;
		}
		pw[i + 15] = carry;
	}

	/* Pack c into words (reuse aw) */
	memset(aw, 0, sizeof(aw));
	for (i = 0; i < 57; i++)
		aw[i >> 2] |= (uint32_t)c[i] << ((i & 3) * 8);

	/* Add c to product */
	carry = 0;
	for (i = 0; i < 15; i++) {
		uint64_t v = (uint64_t)pw[i] + aw[i] + carry;

		pw[i] = v;
		carry = v >> 32;
	}
	for (; i < 30 && carry; i++) {
		uint64_t v = (uint64_t)pw[i] + carry;

		pw[i] = v;
		carry = v >> 32;
	}

	/* Reduce mod L: unpack to bytes, then reduce */
	{
		uint8_t product[116];

		for (i = 0; i < 29; i++) {
			product[4 * i]     = pw[i];
			product[4 * i + 1] = pw[i] >> 8;
			product[4 * i + 2] = pw[i] >> 16;
			product[4 * i + 3] = pw[i] >> 24;
		}
		sc448_reduce(s, product, 114);
	}
}

/* ---------------------------------------------------------------- */
/* Ed448 API                                                        */
/* ---------------------------------------------------------------- */

int mbedcrypto_ed448_gen_keypair(
		uint8_t pub[MBEDCRYPTO_ED448_KEY_SIZE],
		uint8_t priv[2 * MBEDCRYPTO_ED448_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	uint8_t seed[57], hash[114];
	struct ge448_p3 A;
	int ret = 0;

	if (!pub || !priv || !f_rng)
		return -EINVAL;

	/* Generate 57-byte random seed */
	if ((ret = f_rng(p_rng, seed, 57)) != 0)
		return ret;

	/* SHAKE256(seed, 114) */
	shake256(hash, 114, seed, 57);

	/* Clamp scalar */
	hash[0] &= 0xfc;   /* Clear low 2 bits */
	hash[55] |= 0x80;  /* Set high bit of byte 55 */
	hash[56] = 0;       /* Clear byte 56 */

	/* A = [a]*B */
	ge448_scalarmult_base(&A, hash, 57);
	ge448_tobytes(pub, &A);

	/* Private key = seed || pub */
	memcpy(priv, seed, 57);
	memcpy(priv + 57, pub, 57);

	memset(seed, 0, 57);
	memset(hash, 0, 114);
	return 0;
}

int mbedcrypto_ed448_sign(
		uint8_t sig[MBEDCRYPTO_ED448_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t priv[2 * MBEDCRYPTO_ED448_KEY_SIZE])
{
	uint8_t hash[114], nonce_hash[114];
	uint8_t nonce_sc[57], hram_sc[57];
	struct mbedcrypto_sha3_ctx hctx;
	struct ge448_p3 R;

	if (!sig || !priv)
		return -EINVAL;

	/* Hash private key seed: SHAKE256(seed, 114) */
	shake256(hash, 114, priv, 57);
	hash[0] &= 0xfc;
	hash[55] |= 0x80;
	hash[56] = 0;

	/* r = SHAKE256(dom4 || hash[57..113] || msg, 114) mod L */
	mbedcrypto_sha3_init(&hctx);
	mbedcrypto_sha3_start(&hctx, MBEDCRYPTO_SHAKE256);
	mbedcrypto_sha3_update(&hctx, dom4_prefix, sizeof(dom4_prefix));
	mbedcrypto_sha3_update(&hctx, hash + 57, 57);
	if (msg && msg_len)
		mbedcrypto_sha3_update(&hctx, msg, msg_len);
	mbedcrypto_sha3_final(&hctx, nonce_hash, 114);
	sc448_reduce(nonce_sc, nonce_hash, 114);

	/* R = [r]*B */
	ge448_scalarmult_base(&R, nonce_sc, 57);
	ge448_tobytes(sig, &R);  /* sig[0..56] = R */

	/* k = SHAKE256(dom4 || R || A || msg, 114) mod L */
	mbedcrypto_sha3_init(&hctx);
	mbedcrypto_sha3_start(&hctx, MBEDCRYPTO_SHAKE256);
	mbedcrypto_sha3_update(&hctx, dom4_prefix, sizeof(dom4_prefix));
	mbedcrypto_sha3_update(&hctx, sig, 57);           /* R */
	mbedcrypto_sha3_update(&hctx, priv + 57, 57);     /* A */
	if (msg && msg_len)
		mbedcrypto_sha3_update(&hctx, msg, msg_len);
	mbedcrypto_sha3_final(&hctx, nonce_hash, 114);
	sc448_reduce(hram_sc, nonce_hash, 114);

	/* S = (r + k * a) mod L */
	sc448_muladd(sig + 57, hram_sc, hash, nonce_sc);

	memset(hash, 0, sizeof(hash));
	memset(nonce_hash, 0, sizeof(nonce_hash));
	memset(nonce_sc, 0, sizeof(nonce_sc));
	return 0;
}

int mbedcrypto_ed448_verify(
		const uint8_t sig[MBEDCRYPTO_ED448_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t pub[MBEDCRYPTO_ED448_KEY_SIZE])
{
	uint8_t hram_sc[57];
	uint8_t check[57];
	struct ge448_p3 A, sB, kA;
	int ret = 0;

	if (!sig || !pub)
		return -EINVAL;

	/* Decompress public key */
	if ((ret = ge448_frombytes(&A, pub)) != 0)
		return ret;

	/* k = SHAKE256(dom4 || R || A || msg, 114) mod L */
	{
		uint8_t hram_hash[114];
		struct mbedcrypto_sha3_ctx hctx;

		mbedcrypto_sha3_init(&hctx);
		mbedcrypto_sha3_start(&hctx, MBEDCRYPTO_SHAKE256);
		mbedcrypto_sha3_update(&hctx, dom4_prefix, sizeof(dom4_prefix));
		mbedcrypto_sha3_update(&hctx, sig, 57);       /* R */
		mbedcrypto_sha3_update(&hctx, pub, 57);       /* A */
		if (msg && msg_len)
			mbedcrypto_sha3_update(&hctx, msg, msg_len);
		mbedcrypto_sha3_final(&hctx, hram_hash, 114);
		sc448_reduce(hram_sc, hram_hash, 114);
	}

	/* [S]*B */
	ge448_scalarmult_base(&sB, sig + 57, 57);

	/* [k]*A */
	ge448_scalarmult(&kA, hram_sc, 57, &A);

	/* sB = [S]*B - [k]*A */
	ge448_sub(&sB, &sB, &kA);

	ge448_tobytes(check, &sB);

	/* Verify: check == sig[0..56] */
	if (mbedcrypto_ct_memcmp(check, sig, 57) != 0)
		return -EBADMSG;

	return 0;
}