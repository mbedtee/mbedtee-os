// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Ed25519 / X25519 (RFC 8032, RFC 7748)
 *
 * Field arithmetic over GF(2^255-19) using 10 digits of ~25.5
 * bits each.  Montgomery ladder for X25519, extended coordinates
 * for Ed25519.  SHA-512 based signing per RFC 8032.
 */

#include <string.h>
#include <errno.h>

#include <mbedcrypto/curve25519.h>
#include <mbedcrypto/sha512.h>
#include <mbedcrypto/types.h>

/* ---------------------------------------------------------------- */
/* Field element: 10 digits, 26/25/26/25/... bit widths             */
/* ---------------------------------------------------------------- */

typedef int32_t fe[10];

static void fe_0(fe h)
{
	memset(h, 0, 10 * sizeof(int32_t));
}

static void fe_1(fe h)
{
	h[0] = 1;
	memset(h + 1, 0, 9 * sizeof(int32_t));
}

static void fe_copy(fe h, const fe f)
{
	memcpy(h, f, 10 * sizeof(int32_t));
}

/* Load 32 bytes (little-endian) into a field element */
static void fe_frombytes(fe h, const uint8_t *s)
{
	int64_t h0 = mbedcrypto_get_le32(s);
	int64_t h1 = mbedcrypto_get_le32(s + 3) >> 2;
	int64_t h2 = mbedcrypto_get_le32(s + 6) >> 3;
	int64_t h3 = mbedcrypto_get_le32(s + 9) >> 5;
	int64_t h4 = mbedcrypto_get_le32(s + 12) >> 6;
	int64_t h5 = mbedcrypto_get_le32(s + 16);
	int64_t h6 = mbedcrypto_get_le32(s + 19) >> 1;
	int64_t h7 = mbedcrypto_get_le32(s + 22) >> 3;
	int64_t h8 = mbedcrypto_get_le32(s + 25) >> 4;
	int64_t h9 = (mbedcrypto_get_le32(s + 28) & 0x7fffffff) >> 6;
	int64_t carry = 0;

	/* Mask to proper widths */
	h0 &= 0x3ffffff;  h1 &= 0x1ffffff;
	h2 &= 0x3ffffff;  h3 &= 0x1ffffff;
	h4 &= 0x3ffffff;  h5 &= 0x1ffffff;
	h6 &= 0x3ffffff;  h7 &= 0x1ffffff;
	h8 &= 0x3ffffff;

	/* Carry chain */
	carry = (h0 + (1 << 25)) >> 26; h1 += carry; h0 -= carry << 26;
	carry = (h4 + (1 << 25)) >> 26; h5 += carry; h4 -= carry << 26;
	carry = (h1 + (1 << 24)) >> 25; h2 += carry; h1 -= carry << 25;
	carry = (h5 + (1 << 24)) >> 25; h6 += carry; h5 -= carry << 25;
	carry = (h2 + (1 << 25)) >> 26; h3 += carry; h2 -= carry << 26;
	carry = (h6 + (1 << 25)) >> 26; h7 += carry; h6 -= carry << 26;
	carry = (h3 + (1 << 24)) >> 25; h4 += carry; h3 -= carry << 25;
	carry = (h7 + (1 << 24)) >> 25; h8 += carry; h7 -= carry << 25;
	carry = (h4 + (1 << 25)) >> 26; h5 += carry; h4 -= carry << 26;
	carry = (h8 + (1 << 25)) >> 26; h9 += carry; h8 -= carry << 26;

	h[0] = h0; h[1] = h1; h[2] = h2;
	h[3] = h3; h[4] = h4; h[5] = h5;
	h[6] = h6; h[7] = h7; h[8] = h8;
	h[9] = h9;
}

/* Serialize field element to 32 bytes (little-endian, reduced mod p) */
static void fe_tobytes(uint8_t *s, const fe h)
{
	int32_t t[10];
	int32_t q = 0, carry = 0;
	int i = 0;

	memcpy(t, h, sizeof(t));

	/* Full reduction mod 2^255-19 */
	q = (19 * t[9] + (1 << 24)) >> 25;
	for (i = 0; i < 5; i++) {
		q = (t[2 * i] + q) >> 26;
		q = (t[2 * i + 1] + q) >> 25;
	}
	t[0] += 19 * q;

	carry = t[0] >> 26; t[1] += carry; t[0] -= carry << 26;
	carry = t[1] >> 25; t[2] += carry; t[1] -= carry << 25;
	carry = t[2] >> 26; t[3] += carry; t[2] -= carry << 26;
	carry = t[3] >> 25; t[4] += carry; t[3] -= carry << 25;
	carry = t[4] >> 26; t[5] += carry; t[4] -= carry << 26;
	carry = t[5] >> 25; t[6] += carry; t[5] -= carry << 25;
	carry = t[6] >> 26; t[7] += carry; t[6] -= carry << 26;
	carry = t[7] >> 25; t[8] += carry; t[7] -= carry << 25;
	carry = t[8] >> 26; t[9] += carry; t[8] -= carry << 26;
	carry = t[9] >> 25; t[9] -= carry << 25;

	s[0]  = t[0];
	s[1]  = t[0] >> 8;
	s[2]  = t[0] >> 16;
	s[3]  = (t[0] >> 24) | (t[1] << 2);
	s[4]  = t[1] >> 6;
	s[5]  = t[1] >> 14;
	s[6]  = (t[1] >> 22) | (t[2] << 3);
	s[7]  = t[2] >> 5;
	s[8]  = t[2] >> 13;
	s[9]  = (t[2] >> 21) | (t[3] << 5);
	s[10] = t[3] >> 3;
	s[11] = t[3] >> 11;
	s[12] = (t[3] >> 19) | (t[4] << 6);
	s[13] = t[4] >> 2;
	s[14] = t[4] >> 10;
	s[15] = t[4] >> 18;
	s[16] = t[5];
	s[17] = t[5] >> 8;
	s[18] = t[5] >> 16;
	s[19] = (t[5] >> 24) | (t[6] << 1);
	s[20] = t[6] >> 7;
	s[21] = t[6] >> 15;
	s[22] = (t[6] >> 23) | (t[7] << 3);
	s[23] = t[7] >> 5;
	s[24] = t[7] >> 13;
	s[25] = (t[7] >> 21) | (t[8] << 4);
	s[26] = t[8] >> 4;
	s[27] = t[8] >> 12;
	s[28] = (t[8] >> 20) | (t[9] << 6);
	s[29] = t[9] >> 2;
	s[30] = t[9] >> 10;
	s[31] = t[9] >> 18;
}

static void fe_add(fe h, const fe f, const fe g)
{
	int i = 0;

	for (i = 0; i < 10; i++)
		h[i] = f[i] + g[i];
}

static void fe_sub(fe h, const fe f, const fe g)
{
	int i = 0;

	for (i = 0; i < 10; i++)
		h[i] = f[i] - g[i];
}

static void fe_neg(fe h, const fe f)
{
	int i = 0;

	for (i = 0; i < 10; i++)
		h[i] = -f[i];
}

/*
 * h = f * g (schoolbook multiplication with partial reduction)
 *
 * Uses the radix 2^25.5 representation where even digits are 26 bits
 * and odd digits are 25 bits. Cross terms that wrap past digit 9
 * are reduced using 2^255 == 19 (mod p). Odd-index f terms are
 * doubled when the output digit index is even, compensating for
 * the alternating digit widths in the subsequent carry chain.
 */
static void fe_mul(fe h, const fe f, const fe g)
{
	int64_t t[10] = {0};
	int64_t carry = 0;
	int i = 0, j = 0;

	for (i = 0; i < 10; i++) {
		int even_out = !(i & 1);

		/* Direct terms: f[j] * g[i-j] for j = 0..i */
		for (j = 0; j <= i; j++) {
			int64_t fv = (int64_t)f[j];

			if (even_out && (j & 1))
				fv <<= 1;
			t[i] += fv * (int64_t)g[i - j];
		}
		/* Wrapped terms: f[j] * g[10+i-j] * 19 for j = i+1..9 */
		for (j = i + 1; j < 10; j++) {
			int64_t fv = (int64_t)f[j];

			if (even_out && (j & 1))
				fv <<= 1;
			t[i] += fv * ((int64_t)g[10 + i - j] * 19);
		}
	}

	/*
	 * Carry chain: interleaved pairs (i, i+4) for i=0..4, then
	 * wrap t[9] -> t[0]*19, final t[0] -> t[1]. This ordering
	 * guarantees that each digit fits its target width (26/25 bits
	 * alternating) after absorbing incoming carries, providing
	 * the tight bounds needed for subsequent multiplications.
	 */
	for (i = 0; i < 5; i++) {
		int wi = (i & 1) ? 25 : 26;
		int wj = ((i + 4) & 1) ? 25 : 26;

		carry = (t[i] + (1LL << (wi - 1))) >> wi;
		t[i + 1] += carry;
		t[i] -= carry << wi;

		carry = (t[i + 4] + (1LL << (wj - 1))) >> wj;
		t[i + 5] += carry;
		t[i + 4] -= carry << wj;
	}
	/* Wrap carry from digit 9 back to digit 0 (mod 2^255-19) */
	carry = (t[9] + (1LL << 24)) >> 25;
	t[0] += carry * 19;
	t[9] -= carry << 25;
	carry = (t[0] + (1LL << 25)) >> 26;
	t[1] += carry;
	t[0] -= carry << 26;

	for (i = 0; i < 10; i++)
		h[i] = t[i];
}

/* h = f * f */
static void fe_sq(fe h, const fe f)
{
	fe_mul(h, f, f);
}

/* h = f^(2^n) by repeated squaring */
static void fe_sq_n(fe h, const fe f, int n)
{
	fe_sq(h, f);
	while (--n > 0)
		fe_sq(h, h);
}

/* h = 1/f (mod p), via Fermat's little theorem: f^(p-2) */
static void fe_invert(fe h, const fe f)
{
	fe t0, t1, t2, t3;

	fe_sq(t0, f);         /* t0 = f^2 */
	fe_sq_n(t1, t0, 2);   /* t1 = f^8 */
	fe_mul(t1, f, t1);    /* t1 = f^9 */
	fe_mul(t0, t0, t1);   /* t0 = f^11 */
	fe_sq(t2, t0);        /* t2 = f^22 */
	fe_mul(t1, t1, t2);   /* t1 = f^(2^5-1) */
	fe_sq_n(t2, t1, 5);   /* t2 = f^(2^10-2^5) */
	fe_mul(t1, t2, t1);   /* t1 = f^(2^10-1) */
	fe_sq_n(t2, t1, 10);  /* t2 = f^(2^20-2^10) */
	fe_mul(t2, t2, t1);   /* t2 = f^(2^20-1) */
	fe_sq_n(t3, t2, 20);  /* t3 = f^(2^40-2^20) */
	fe_mul(t2, t3, t2);   /* t2 = f^(2^40-1) */
	fe_sq_n(t2, t2, 10);  /* t2 = f^(2^50-2^10) */
	fe_mul(t1, t2, t1);   /* t1 = f^(2^50-1) */
	fe_sq_n(t2, t1, 50);
	fe_mul(t2, t2, t1);   /* t2 = f^(2^100-1) */
	fe_sq_n(t3, t2, 100);
	fe_mul(t2, t3, t2);   /* t2 = f^(2^200-1) */
	fe_sq_n(t2, t2, 50);
	fe_mul(t1, t2, t1);   /* t1 = f^(2^250-1) */
	fe_sq_n(t1, t1, 5);
	fe_mul(h, t1, t0);    /* h = f^(2^255-21) = f^(p-2) */
}

/* Compute f^((p-5)/8) = f^(2^252-3), needed for sqrt */
static void fe_pow2523(fe h, const fe f)
{
	fe t0, t1, t2;

	fe_sq(t0, f);
	fe_sq(t1, t0);
	fe_sq(t1, t1);
	fe_mul(t1, f, t1);
	fe_mul(t0, t0, t1);
	fe_sq(t0, t0);
	fe_mul(t0, t1, t0);
	fe_sq_n(t1, t0, 5);
	fe_mul(t0, t1, t0);
	fe_sq_n(t1, t0, 10);
	fe_mul(t1, t1, t0);
	fe_sq_n(t2, t1, 20);
	fe_mul(t1, t2, t1);
	fe_sq_n(t1, t1, 10);
	fe_mul(t0, t1, t0);
	fe_sq_n(t1, t0, 50);
	fe_mul(t1, t1, t0);
	fe_sq_n(t2, t1, 100);
	fe_mul(t1, t2, t1);
	fe_sq_n(t1, t1, 50);
	fe_mul(t0, t1, t0);
	fe_sq(t0, t0);
	fe_sq(t0, t0);
	fe_mul(h, t0, f);
}

/* Check if f is negative (LSB of reduced form) */
static int fe_isneg(const fe f)
{
	uint8_t s[32];

	fe_tobytes(s, f);
	return s[0] & 1;
}

/* Check if f is zero */
static int fe_isnonzero(const fe f)
{
	uint8_t s[32];
	int i, acc = 0;

	fe_tobytes(s, f);
	for (i = 0; i < 32; i++)
		acc |= s[i];
	return acc;
}

/* Constant-time swap: swap f and g if b == 1 */
static void fe_cswap(fe f, fe g, int b)
{
	int32_t mask = -(int32_t)b;
	int32_t t = 0;
	int i = 0;

	for (i = 0; i < 10; i++) {
		t = mask & (f[i] ^ g[i]);
		f[i] ^= t;
		g[i] ^= t;
	}
}

/* h = 121666 * f */
static void fe_mul121666(fe h, const fe f)
{
	int64_t carry = 0;
	int64_t t[10];
	int i = 0;

	for (i = 0; i < 10; i++)
		t[i] = (int64_t)f[i] * 121666;

	carry = (t[9] + (1LL << 24)) >> 25;
	t[0] += carry * 19; t[9] -= carry << 25;

	for (i = 0; i < 9; i++) {
		int bits = (i & 1) ? 24 : 25;

		carry = (t[i] + (1LL << bits)) >> (bits + 1);
		t[i + 1] += carry;
		t[i] -= carry << (bits + 1);
	}

	for (i = 0; i < 10; i++)
		h[i] = t[i];
}

/* ---------------------------------------------------------------- */
/* X25519: Montgomery ladder scalar multiplication                  */
/* ---------------------------------------------------------------- */

/* Clamp a scalar for X25519 */
static void x25519_clamp(uint8_t e[32])
{
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;
}

/*
 * Scalar multiplication on the Montgomery curve.
 * Writes the u-coordinate of [scalar]*point to out.
 */
static void x25519_scalar_mult(uint8_t out[32],
		const uint8_t scalar[32], const uint8_t point[32])
{
	fe x1, x2, z2, x3, z3, tmp0, tmp1;
	uint8_t e[32];
	int swap = 0, b, i;

	memcpy(e, scalar, 32);

	fe_frombytes(x1, point);
	fe_1(x2);
	fe_0(z2);
	fe_copy(x3, x1);
	fe_1(z3);

	for (i = 254; i >= 0; i--) {
		b = (e[i >> 3] >> (i & 7)) & 1;
		swap ^= b;
		fe_cswap(x2, x3, swap);
		fe_cswap(z2, z3, swap);
		swap = b;

		fe_sub(tmp0, x3, z3);
		fe_sub(tmp1, x2, z2);
		fe_add(x2, x2, z2);
		fe_add(z2, x3, z3);
		fe_mul(z3, tmp0, x2);
		fe_mul(z2, z2, tmp1);
		fe_sq(tmp0, tmp1);
		fe_sq(tmp1, x2);
		fe_add(x3, z3, z2);
		fe_sub(z2, z3, z2);
		fe_mul(x2, tmp1, tmp0);
		fe_sub(tmp1, tmp1, tmp0);
		fe_sq(z2, z2);
		fe_mul121666(z3, tmp1);
		fe_sq(x3, x3);
		fe_add(tmp0, tmp0, z3);
		fe_mul(z3, x1, z2);
		fe_mul(z2, tmp1, tmp0);
	}

	fe_cswap(x2, x3, swap);
	fe_cswap(z2, z3, swap);

	fe_invert(z2, z2);
	fe_mul(x2, x2, z2);
	fe_tobytes(out, x2);
}

/* The base point u-coordinate (9) for Curve25519 */
static const uint8_t x25519_basepoint[32] = { 9 };

int mbedcrypto_x25519_calc_public(
		uint8_t pub[MBEDCRYPTO_X25519_KEY_SIZE],
		const uint8_t priv[MBEDCRYPTO_X25519_KEY_SIZE])
{
	uint8_t e[32];

	if (!pub || !priv)
		return -EINVAL;

	memcpy(e, priv, 32);
	x25519_clamp(e);
	x25519_scalar_mult(pub, e, x25519_basepoint);

	memset(e, 0, 32);
	return 0;
}

int mbedcrypto_x25519_calc_secret(
		uint8_t secret[MBEDCRYPTO_X25519_KEY_SIZE],
		const uint8_t our_priv[MBEDCRYPTO_X25519_KEY_SIZE],
		const uint8_t their_pub[MBEDCRYPTO_X25519_KEY_SIZE])
{
	uint8_t e[32];

	if (!secret || !our_priv || !their_pub)
		return -EINVAL;

	memcpy(e, our_priv, 32);
	x25519_clamp(e);
	x25519_scalar_mult(secret, e, their_pub);

	memset(e, 0, 32);
	return 0;
}

int mbedcrypto_x25519_gen_keypair(
		uint8_t pub[MBEDCRYPTO_X25519_KEY_SIZE],
		uint8_t priv[MBEDCRYPTO_X25519_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;

	if (!pub || !priv || !f_rng)
		return -EINVAL;

	if ((ret = f_rng(p_rng, priv, 32)) != 0)
		return ret;

	return mbedcrypto_x25519_calc_public(pub, priv);
}

/* ---------------------------------------------------------------- */
/* Ed25519: Extended coordinates (X:Y:Z:T) with Y^2-X^2=1+d*X^2*Y^2 */
/* ---------------------------------------------------------------- */

/* d = -121665/121666 mod p */
static const fe ed25519_d = {
	-10913610, 13857413, -15372611, 6949391, 114729,
	-8787816, -6275908, -3247719, -18696448, -12055116
};

/* 2*d */
static const fe ed25519_2d = {
	-21827239, -5839606, -30745221, 13898782, 229458,
	15978800, -12551817, -6495438, 29715968, 9444199
};

/* sqrt(-1) mod p */
static const fe ed25519_sqrtm1 = {
	-32595792, -7943725, 9377950, 3500415, 12389472,
	-272473, -25146209, -2005654, 326686, 11406482
};

/* Basepoint B */
static const fe ed25519_by = {
	-26843560, -6710886, 13421773, -13421773, 26843546,
	6710886, -13421773, 13421773, -26843546, 26843546
};
static const fe ed25519_bx = {
	-14297830, -7645148, 16144683, -16471763, 27570974,
	-2696100, -26142465, 8378389, 20764389, 8758491
};

struct ge_p3 { /* extended point */
	fe X, Y, Z, T;
};

struct ge_p2 { /* projective point */
	fe X, Y, Z;
};

struct ge_p1p1 { /* completed point */
	fe X, Y, Z, T;
};

struct ge_precomp { /* precomputed for mixed addition */
	fe ypx, ymx, xy2d;
};

struct ge_cached {
	fe YpX, YmX, Z, T2d;
};

static void ge_p3_0(struct ge_p3 *h)
{
	fe_0(h->X); fe_1(h->Y); fe_1(h->Z); fe_0(h->T);
}

static void ge_p1p1_to_p3(struct ge_p3 *r, const struct ge_p1p1 *p)
{
	fe_mul(r->X, p->X, p->T);
	fe_mul(r->Y, p->Y, p->Z);
	fe_mul(r->Z, p->Z, p->T);
	fe_mul(r->T, p->X, p->Y);
}

/* Point doubling: r = 2*p */
static void ge_p2_dbl(struct ge_p1p1 *r, const struct ge_p2 *p)
{
	fe t0;

	fe_sq(r->X, p->X);      /* A = X^2 */
	fe_sq(r->Z, p->Y);      /* B = Y^2 */
	fe_sq(r->T, p->Z);      /* C = 2*Z^2 */
	fe_add(r->T, r->T, r->T);
	fe_add(r->Y, p->X, p->Y);
	fe_sq(t0, r->Y);
	fe_add(r->Y, r->Z, r->X);  /* B+A */
	fe_sub(r->Z, r->Z, r->X);  /* B-A */
	fe_sub(r->X, t0, r->Y);    /* E = (X+Y)^2 - (B+A) */
	fe_sub(r->T, r->T, r->Z);  /* C - (B-A) = H */
}

/* r = p + q (extended + cached) */
static void ge_add(struct ge_p1p1 *r, const struct ge_p3 *p, const struct ge_cached *q)
{
	fe t0;

	fe_add(r->X, p->Y, p->X);  /* Y+X */
	fe_sub(r->Y, p->Y, p->X);  /* Y-X */
	fe_mul(r->Z, r->X, q->YpX);
	fe_mul(r->Y, r->Y, q->YmX);
	fe_mul(r->T, q->T2d, p->T);
	fe_mul(r->X, p->Z, q->Z);
	fe_add(t0, r->X, r->X);
	fe_sub(r->X, r->Z, r->Y);
	fe_add(r->Y, r->Z, r->Y);
	fe_add(r->Z, t0, r->T);
	fe_sub(r->T, t0, r->T);
}

static void ge_p3_to_cached(struct ge_cached *r, const struct ge_p3 *p)
{
	fe_add(r->YpX, p->Y, p->X);
	fe_sub(r->YmX, p->Y, p->X);
	fe_copy(r->Z, p->Z);
	fe_mul(r->T2d, p->T, ed25519_2d);
}

/* Decompress a point from 32-byte compressed form */
static int ge_frombytes(struct ge_p3 *h, const uint8_t *s)
{
	fe u, v, v3, vxx, check;
	int sign = 0;

	sign = s[31] >> 7;
	fe_frombytes(h->Y, s);
	fe_1(h->Z);

	/* u = y^2 - 1, v = d*y^2 + 1 */
	fe_sq(u, h->Y);
	fe_mul(v, u, ed25519_d);
	fe_sub(u, u, h->Z); /* y^2-1 */
	fe_add(v, v, h->Z); /* dy^2+1 */

	/* x = (u/v)^((p+3)/8) = u * v^3 * (u * v^7)^((p-5)/8) */
	fe_sq(v3, v);
	fe_mul(v3, v3, v);    /* v3 = v^3 */
	fe_sq(h->X, v3);
	fe_mul(h->X, h->X, v); /* v^7 */
	fe_mul(h->X, h->X, u); /* u*v^7 */
	fe_pow2523(h->X, h->X); /* (u*v^7)^((p-5)/8) */
	fe_mul(h->X, h->X, v3);
	fe_mul(h->X, h->X, u); /* x = u*v^3*(u*v^7)^((p-5)/8) */

	/* Check: v*x^2 == u ? */
	fe_sq(vxx, h->X);
	fe_mul(vxx, vxx, v);
	fe_sub(check, vxx, u);
	if (fe_isnonzero(check)) {
		fe_add(check, vxx, u);
		if (fe_isnonzero(check))
			return -EINVAL;
		fe_mul(h->X, h->X, ed25519_sqrtm1);
	}

	if (fe_isneg(h->X) != sign)
		fe_neg(h->X, h->X);

	fe_mul(h->T, h->X, h->Y);
	return 0;
}

/* Compress a point to 32 bytes */
static void ge_tobytes(uint8_t *s, const struct ge_p3 *h)
{
	fe recip, x, y;

	fe_invert(recip, h->Z);
	fe_mul(x, h->X, recip);
	fe_mul(y, h->Y, recip);
	fe_tobytes(s, y);
	s[31] ^= fe_isneg(x) << 7;
}

/* Scalar multiplication: r = [a]*B using 4-bit windows */
#ifdef CONFIG_MBEDCRYPTO_ED25519_BTABLE
/*
 * Precomputed basepoint table: btab[i] = [i]*B in struct ge_cached form.
 * Built once at first use. 16 entries x 160 bytes = 2.5 KB BSS.
 */
static struct ge_cached ed25519_btab[16];
static int ed25519_btab_ready;

static void ed25519_build_btab(void)
{
	struct ge_p3 bp, P;
	struct ge_p1p1 t;
	struct ge_cached cb;
	struct ge_p3 zero;
	int i = 0;

	if (ed25519_btab_ready)
		return;

	/* base point */
	fe_copy(bp.X, ed25519_bx);
	fe_copy(bp.Y, ed25519_by);
	fe_1(bp.Z);
	fe_mul(bp.T, bp.X, bp.Y);

	/* [0]B = identity */
	ge_p3_0(&zero);
	ge_p3_to_cached(&ed25519_btab[0], &zero);

	/* [1]B = B */
	ge_p3_to_cached(&ed25519_btab[1], &bp);

	/* [i]B = [i-1]B + B */
	ge_p3_to_cached(&cb, &bp);
	P = bp;
	for (i = 2; i <= 15; i++) {
		ge_add(&t, &P, &cb);
		ge_p1p1_to_p3(&P, &t);
		ge_p3_to_cached(&ed25519_btab[i], &P);
	}
	ed25519_btab_ready = 1;
}

static void ge_scalarmult_base(struct ge_p3 *r, const uint8_t *a)
{
	struct ge_p1p1 t;
	struct ge_p2 s;
	int i = 0, d = 0, w = 0;

	ed25519_build_btab();
	ge_p3_0(r);

	/* Process 64 unsigned 4-bit windows from MSB */
	for (i = 63; i >= 0; i--) {
		/* 4 doublings */
		for (d = 0; d < 4; d++) {
			fe_copy(s.X, r->X);
			fe_copy(s.Y, r->Y);
			fe_copy(s.Z, r->Z);
			ge_p2_dbl(&t, &s);
			ge_p1p1_to_p3(r, &t);
		}

		/* Extract 4-bit window value */
		w = (a[i >> 1] >> ((i & 1) * 4)) & 0xf;
		if (w != 0) {
			ge_add(&t, r, &ed25519_btab[w]);
			ge_p1p1_to_p3(r, &t);
		}
	}
}
#else
static void ge_scalarmult_base(struct ge_p3 *r, const uint8_t *a)
{
	struct ge_p3 bp;
	struct ge_p1p1 t;
	struct ge_p2 s;
	struct ge_cached cache;
	int i = 0, b = 0;

	/* Set base point */
	fe_copy(bp.X, ed25519_bx);
	fe_copy(bp.Y, ed25519_by);
	fe_1(bp.Z);
	fe_mul(bp.T, bp.X, bp.Y);
	ge_p3_to_cached(&cache, &bp);

	ge_p3_0(r);

	for (i = 255; i >= 0; i--) {
		/* Double */
		fe_copy(s.X, r->X);
		fe_copy(s.Y, r->Y);
		fe_copy(s.Z, r->Z);

		ge_p2_dbl(&t, &s);
		ge_p1p1_to_p3(r, &t);

		/* Add base point if bit is set */
		b = (a[i >> 3] >> (i & 7)) & 1;
		if (b) {
			ge_add(&t, r, &cache);
			ge_p1p1_to_p3(r, &t);
		}
	}
}
#endif

/*
 * Variable-base scalar multiplication: r = [a]*P
 * Simple double-and-add.
 */
static void ge_scalarmult(struct ge_p3 *r, const uint8_t *a, const struct ge_p3 *p)
{
	struct ge_p1p1 t;
	struct ge_p2 s;
	struct ge_cached cache;
	int i = 0, b = 0;

	ge_p3_0(r);

	for (i = 255; i >= 0; i--) {
		fe_copy(s.X, r->X);
		fe_copy(s.Y, r->Y);
		fe_copy(s.Z, r->Z);

		ge_p2_dbl(&t, &s);
		ge_p1p1_to_p3(r, &t);

		b = (a[i >> 3] >> (i & 7)) & 1;
		if (b) {
			ge_p3_to_cached(&cache, p);
			ge_add(&t, r, &cache);
			ge_p1p1_to_p3(r, &t);
		}
	}
}

/* SHA-512 helper */
static void sha512(const uint8_t *data, size_t len, uint8_t out[64])
{
	struct mbedcrypto_sha512_ctx ctx;

	mbedcrypto_sha512_init(&ctx, 0);
	mbedcrypto_sha512_update(&ctx, data, len);
	mbedcrypto_sha512_final(&ctx, out);
}

/*
 * Ed25519 group order:
 * L = 2^252 + 27742317777372353535851937790883648493
 *
 * In 21-bit radix, the low 6 "digits" of L are stored as signed
 * coefficients. Reduction eliminates high digits by distributing
 * these coefficients into lower positions.
 */
static const int64_t sc_l_c[6] = {
	666643, 470296, 654183, -997805, 136657, -683901
};

/*
 * Load n 21-bit digits from a little-endian byte buffer.
 * Byte offsets and right-shifts cycle with period 8, covering
 * 21 bytes per group. The last digit is unmasked (absorbs any
 * remaining high bits).
 */
static void sc_load_digits(int64_t *t, const uint8_t *s, int n)
{
	static const uint8_t base_off[8] = {0, 2, 5, 7, 10, 13, 15, 18};
	static const uint8_t shift[8]    = {0, 5, 2, 7,  4,  1,  6,  3};
	int i = 0;

	for (i = 0; i < n; i++) {
		int off = 21 * (i >> 3) + base_off[i & 7];
		int64_t v = mbedcrypto_get_le32(s + off) >> shift[i & 7];

		t[i] = (i < n - 1) ? (v & 0x1fffff) : v;
	}
}

/*
 * Eliminate digit t[hi] by distributing it into t[lo..lo+5]
 * using the group-order coefficients, then zero t[hi].
 */
static inline void sc_elim(int64_t *t, int hi, int lo)
{
	int k = 0;

	for (k = 0; k < 6; k++)
		t[lo + k] += t[hi] * sc_l_c[k];
	t[hi] = 0;
}

/*
 * Serialize 12 21-bit digits into 32 little-endian bytes.
 * Digit i occupies bits [21*i, 21*(i+1)) in the output.
 */
static void sc_tobytes(uint8_t *s, const int64_t *t)
{
	int i = 0;

	memset(s, 0, 32);
	for (i = 0; i < 12; i++) {
		int bp = (21 * i) >> 3;
		int bo = (21 * i) & 7;
		uint32_t v = (uint32_t)t[i] & 0x1fffff;

		s[bp]     |= v << bo;
		s[bp + 1] |= v >> (8 - bo);
		s[bp + 2] |= v >> (16 - bo);
		if (bo > 3)
			s[bp + 3] |= v >> (24 - bo);
	}
}

/*
 * Reduce a 64-byte little-endian integer mod the group order L.
 * L = 2^252 + 27742317777372353535851937790883648493
 *
 * Decomposes the 512-bit value into 24 digits of 21 bits, then
 * reduces in two passes (high digits -> middle -> low) with
 * interleaved carry chains, finishing with a sequential carry.
 */
static void sc_reduce(uint8_t *s)
{
	int64_t t[24], carry;
	int i = 0, j = 0;

	sc_load_digits(t, s, 24);

	/* First pass: eliminate t[23..18] into t[11..6] */
	for (j = 23; j >= 18; j--)
		sc_elim(t, j, j - 12);

	/* Interleaved carry: even 6..16, then odd 7..15 */
	for (i = 6; i <= 16; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}
	for (i = 7; i <= 15; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}

	/* Second pass: eliminate t[17..12] into t[5..0] */
	for (j = 17; j >= 12; j--)
		sc_elim(t, j, j - 12);

	/* Interleaved carry: even 0..10, then odd 1..11 */
	for (i = 0; i <= 10; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}
	for (i = 1; i <= 11; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}

	/* Third pass: reduce any residual in t[12] */
	sc_elim(t, 12, 0);

	/* Sequential carry chain */
	for (i = 0; i <= 10; i++) {
		carry = t[i] >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}

	/* Fourth pass: carry from t[11] may produce t[12] > 0 */
	carry = t[11] >> 21;
	t[12] = carry;
	t[11] -= carry << 21;
	sc_elim(t, 12, 0);

	/* Final sequential carry */
	for (i = 0; i <= 10; i++) {
		carry = t[i] >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}

	sc_tobytes(s, t);
	memset(s + 32, 0, 32);
}

/*
 * Compute s = (c + a * b) mod L
 *
 * Inputs a, b, c are 32-byte little-endian scalars (reduced mod L).
 * The 12x12 schoolbook product a*b is accumulated into 24 digits,
 * then c is added and the sum is reduced mod L.
 */
static void sc_muladd(uint8_t *s,
		const uint8_t *a, const uint8_t *b, const uint8_t *c)
{
	int64_t al[12], bl[12], cl[12], t[24], carry;
	int i = 0, j = 0;

	sc_load_digits(al, a, 12);
	sc_load_digits(bl, b, 12);
	sc_load_digits(cl, c, 12);

	/* t = a * b (schoolbook multiplication) */
	memset(t, 0, sizeof(t));
	for (i = 0; i < 12; i++)
		for (j = 0; j < 12; j++)
			t[i + j] += al[i] * bl[j];

	/* t += c */
	for (i = 0; i < 12; i++)
		t[i] += cl[i];

	/* Initial carry chain to normalize (product digits can be large) */
	for (i = 0; i <= 22; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}
	for (i = 1; i <= 21; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}

	/* First pass: eliminate t[23..18] into t[11..6] */
	for (j = 23; j >= 18; j--)
		sc_elim(t, j, j - 12);

	/* Interleaved carry: even 6..16, then odd 7..15 */
	for (i = 6; i <= 16; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}
	for (i = 7; i <= 15; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}

	/* Second pass: eliminate t[17..12] into t[5..0] */
	for (j = 17; j >= 12; j--)
		sc_elim(t, j, j - 12);

	/* Interleaved carry: even 0..10, then odd 1..11 */
	for (i = 0; i <= 10; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}
	for (i = 1; i <= 11; i += 2) {
		carry = (t[i] + (1 << 20)) >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}

	/* Third pass: reduce any residual in t[12] */
	sc_elim(t, 12, 0);

	/* Sequential carry chain */
	for (i = 0; i <= 10; i++) {
		carry = t[i] >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}

	/* Fourth pass: carry from t[11] may produce t[12] > 0 */
	carry = t[11] >> 21;
	t[12] = carry;
	t[11] -= carry << 21;
	sc_elim(t, 12, 0);

	/* Final sequential carry */
	for (i = 0; i <= 10; i++) {
		carry = t[i] >> 21;
		t[i + 1] += carry;
		t[i] -= carry << 21;
	}

	sc_tobytes(s, t);
}

/* ---------------------------------------------------------------- */
/* Ed25519 API                                                      */
/* ---------------------------------------------------------------- */

int mbedcrypto_ed25519_gen_keypair(
		uint8_t pub[MBEDCRYPTO_ED25519_KEY_SIZE],
		uint8_t priv[2 * MBEDCRYPTO_ED25519_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	uint8_t seed[32], hash[64];
	struct ge_p3 A;
	int ret = 0;

	if (!pub || !priv || !f_rng)
		return -EINVAL;

	/* Generate 32-byte random seed */
	if ((ret = f_rng(p_rng, seed, 32)) != 0)
		return ret;

	/* Hash seed to get scalar a (first 32 bytes) and nonce prefix */
	sha512(seed, 32, hash);
	hash[0] &= 248;
	hash[31] &= 63;
	hash[31] |= 64;

	/* A = [a]*B */
	ge_scalarmult_base(&A, hash);
	ge_tobytes(pub, &A);

	/* Private key = seed || pub */
	memcpy(priv, seed, 32);
	memcpy(priv + 32, pub, 32);

	memset(seed, 0, 32);
	memset(hash, 0, 64);
	return 0;
}

int mbedcrypto_ed25519_sign(
		uint8_t sig[MBEDCRYPTO_ED25519_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t priv[2 * MBEDCRYPTO_ED25519_KEY_SIZE])
{
	uint8_t hash[64], nonce[64], hram[64];
	struct mbedcrypto_sha512_ctx hctx;
	struct ge_p3 R;

	if (!sig || !priv)
		return -EINVAL;

	/* Hash private key seed */
	sha512(priv, 32, hash);
	hash[0] &= 248;
	hash[31] &= 63;
	hash[31] |= 64;

	/* r = H(hash[32..63] || msg) mod L */
	mbedcrypto_sha512_init(&hctx, 0);
	mbedcrypto_sha512_update(&hctx, hash + 32, 32);
	if (msg && msg_len)
		mbedcrypto_sha512_update(&hctx, msg, msg_len);
	mbedcrypto_sha512_final(&hctx, nonce);
	sc_reduce(nonce);

	/* R = [r]*B */
	ge_scalarmult_base(&R, nonce);
	ge_tobytes(sig, &R); /* sig[0..31] = R */

	/* S = (r + H(R||A||msg) * a) mod L */
	mbedcrypto_sha512_init(&hctx, 0);
	mbedcrypto_sha512_update(&hctx, sig, 32);       /* R */
	mbedcrypto_sha512_update(&hctx, priv + 32, 32); /* A (public key) */
	if (msg && msg_len)
		mbedcrypto_sha512_update(&hctx, msg, msg_len);
	mbedcrypto_sha512_final(&hctx, hram);
	sc_reduce(hram);

	sc_muladd(sig + 32, hram, hash, nonce); /* S = r + H(R||A||msg)*a */

	memset(hash, 0, sizeof(hash));
	memset(nonce, 0, sizeof(nonce));
	return 0;
}

/*
 * Ed25519 group order L (little-endian).
 * L = 2^252 + 27742317777372353535851937790883648493
 */
static const uint8_t ed25519_order[32] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Check that 32-byte LE scalar s is in [0, L). Constant-time. */
static int sc_check(const uint8_t *s)
{
	int i = 0;
	unsigned int borrow = 0;

	for (i = 0; i < 32; i++) {
		unsigned int diff = s[i] - ed25519_order[i] - borrow;

		borrow = (diff >> 8) & 1;
	}

	return borrow ? 0 : -EBADMSG;
}

int mbedcrypto_ed25519_verify(
		const uint8_t sig[MBEDCRYPTO_ED25519_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t pub[MBEDCRYPTO_ED25519_KEY_SIZE])
{
	uint8_t hram[64], check[32];
	struct mbedcrypto_sha512_ctx hctx;
	struct ge_p3 A, R_check;
	struct ge_p1p1 t;
	struct ge_cached A_cache;
	int ret = 0;

	if (!sig || !pub)
		return -EINVAL;

	/* Reject S >= L (signature malleability, RFC 8032 Sec.5.1.7) */
	if (sc_check(sig + 32) != 0)
		return -EBADMSG;

	/* Decompress public key A */
	if ((ret = ge_frombytes(&A, pub)) != 0)
		return ret;

	/* Negate A for computing [S]*B - [H]*A = R */
	fe_neg(A.X, A.X);
	fe_neg(A.T, A.T);

	/* H = SHA-512(R || A || msg) mod L */
	mbedcrypto_sha512_init(&hctx, 0);
	mbedcrypto_sha512_update(&hctx, sig, 32);     /* R */
	mbedcrypto_sha512_update(&hctx, pub, 32);     /* A */
	if (msg && msg_len)
		mbedcrypto_sha512_update(&hctx, msg, msg_len);
	mbedcrypto_sha512_final(&hctx, hram);
	sc_reduce(hram);

	/* R_check = [S]*B + [H]*(-A) = [S]*B - [H]*A */
	/* Use double scalar multiplication */
	{
		struct ge_p3 sB_p3, hA;

		ge_scalarmult_base(&sB_p3, sig + 32);
		ge_scalarmult(&hA, hram, &A);

		ge_p3_to_cached(&A_cache, &hA);
		ge_add(&t, &sB_p3, &A_cache);
		ge_p1p1_to_p3(&R_check, &t);
	}

	ge_tobytes(check, &R_check);

	/* Verify: check == sig[0..31] (R) */
	if (mbedcrypto_ct_memcmp(check, sig, 32) != 0)
		return -EBADMSG;

	return 0;
}
