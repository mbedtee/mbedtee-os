// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Big number (arbitrary precision) integer arithmetic
 *
 * Uses adaptive word size: 64-bit on 64-bit platforms,
 * 32-bit on 32-bit platforms (ARM32, RISCV32, MIPS32, MicroBlaze).
 * Binary GCD (Stein's algorithm) for O(n^2) performance.
 */

#include <stdlib.h>
#include <string.h>

#include <mbedcrypto/bignum.h>

/* Number of leading zeros in a bn_word_t word. */
static inline int bn_clz(bn_word_t x)
{
	int n = 0;

	if (x == 0)
		return BN_WORD_BITS;

#if BN_WORD_BITS == 64
	if (!(x & 0xFFFFFFFF00000000ULL)) { n += 32; x <<= 32; }
	if (!(x & 0xFFFF000000000000ULL)) { n += 16; x <<= 16; }
	if (!(x & 0xFF00000000000000ULL)) { n +=  8; x <<=  8; }
	if (!(x & 0xF000000000000000ULL)) { n +=  4; x <<=  4; }
	if (!(x & 0xC000000000000000ULL)) { n +=  2; x <<=  2; }
	if (!(x & 0x8000000000000000ULL)) n +=  1;
#else
	if (!(x & 0xFFFF0000)) { n += 16; x <<= 16; }
	if (!(x & 0xFF000000)) { n +=  8; x <<=  8; }
	if (!(x & 0xF0000000)) { n +=  4; x <<=  4; }
	if (!(x & 0xC0000000)) { n +=  2; x <<=  2; }
	if (!(x & 0x80000000)) n +=  1;
#endif

	return n;
}

/* Count trailing zeros in a bn_word_t word. */
static inline int bn_ctz(bn_word_t x)
{
	int n = 0;

	if (x == 0)
		return BN_WORD_BITS;

#if BN_WORD_BITS == 64
	if (!(x & 0x00000000FFFFFFFFULL)) { n += 32; x >>= 32; }
#endif
	if (!(x & 0x0000FFFF)) { n += 16; x >>= 16; }
	if (!(x & 0x000000FF)) { n +=  8; x >>=  8; }
	if (!(x & 0x0000000F)) { n +=  4; x >>=  4; }
	if (!(x & 0x00000003)) { n +=  2; x >>=  2; }
	if (!(x & 0x00000001)) n +=  1;

	return n;
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                         */
/* ------------------------------------------------------------------ */

void mbedcrypto_bn_init(struct mbedcrypto_bignum *X)
{
	X->neg = 0;
	X->used = 0;
	X->capacity = 0;
	X->data = NULL;
}

void mbedcrypto_bn_cleanup(struct mbedcrypto_bignum *X)
{
	if (X->data && X->capacity > 0) {
		memset(X->data, 0, X->capacity * sizeof(bn_word_t));
		free(X->data);
	}
	X->neg = 0;
	X->used = 0;
	X->capacity = 0;
	X->data = NULL;
}

int mbedcrypto_bn_expand(struct mbedcrypto_bignum *X, size_t nwords)
{
	bn_word_t *p = NULL;

	if (nwords <= X->capacity) {
		/* Buffer has enough capacity - just zero new words. */
		if (nwords > X->used) {
			memset(X->data + X->used, 0,
			       (nwords - X->used) * sizeof(bn_word_t));
			X->used = nwords;
		}
		return 0;
	}

	p = calloc(nwords, sizeof(bn_word_t));
	if (!p)
		return -ENOMEM;

	if (X->data) {
		memcpy(p, X->data, X->used * sizeof(bn_word_t));
		if (X->capacity > 0) {
			memset(X->data, 0,
			       X->capacity * sizeof(bn_word_t));
			free(X->data);
		}
	}

	X->data = p;
	X->used = nwords;
	X->capacity = nwords;

	return 0;
}

int mbedcrypto_bn_shrink(struct mbedcrypto_bignum *X, size_t min)
{
	bn_word_t *p = NULL;
	size_t i = 0;

	/* Find the actual number of used words. */
	for (i = X->used; i > 0; i--) {
		if (X->data[i - 1] != 0)
			break;
	}

	if (i < min)
		i = min;

	if (i == X->used)
		return 0;

	if (i > 0) {
		p = calloc(i, sizeof(bn_word_t));
		if (!p)
			return -ENOMEM;
		memcpy(p, X->data, i * sizeof(bn_word_t));
	} else
		p = NULL;

	if (X->data && X->capacity > 0) {
		memset(X->data, 0, X->capacity * sizeof(bn_word_t));
		free(X->data);
	}

	X->data = p;
	X->used = i;
	X->capacity = i;

	return 0;
}

int mbedcrypto_bn_copy(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *Y)
{
	int ret = 0;
	size_t i = 0;

	if (X == Y)
		return 0;

	/* Find actual size of Y. */
	for (i = Y->used; i > 0; i--) {
		if (Y->data[i - 1] != 0)
			break;
	}

	if (i == 0) {
		mbedcrypto_bn_cleanup(X);
		return 0;
	}

	if ((ret = mbedcrypto_bn_expand(X, i)) != 0)
		return ret;

	memset(X->data, 0, X->used * sizeof(bn_word_t));
	memcpy(X->data, Y->data, i * sizeof(bn_word_t));
	X->neg = Y->neg;

	return 0;
}

void mbedcrypto_bn_swap(struct mbedcrypto_bignum *X,
		struct mbedcrypto_bignum *Y)
{
	struct mbedcrypto_bignum T = *X;

	*X = *Y;
	*Y = T;
}

/* ------------------------------------------------------------------ */
/*  Set / get small values                                             */
/* ------------------------------------------------------------------ */

int mbedcrypto_bn_set_word(struct mbedcrypto_bignum *X, int z)
{
	int ret = 0;

	if ((ret = mbedcrypto_bn_expand(X, 1)) != 0)
		return ret;

	memset(X->data, 0, X->used * sizeof(bn_word_t));

	/*
	 * Compute |z| using unsigned subtraction in bn_word_t width.
	 * Direct -(bn_word_t)z is undefined behavior when z == INT32_MIN,
	 * and GCC may exploit that UB. Instead, (bn_word_t)z sign-extends
	 * to full width first (well-defined), then subtracting from zero
	 * in bn_word_t width gives the correct absolute value.
	 */
	X->data[0] = (z < 0) ? (bn_word_t)0 - (bn_word_t)z : (bn_word_t)z;
	X->neg = (z < 0);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Bit operations                                                     */
/* ------------------------------------------------------------------ */

size_t mbedcrypto_bn_bit_count(const struct mbedcrypto_bignum *X)
{
	size_t i = 0;

	if (X->used == 0)
		return 0;

	for (i = X->used; i > 0; i--) {
		if (X->data[i - 1] != 0)
			return (i * BN_WORD_BITS) -
				bn_clz(X->data[i - 1]);
	}

	return 0;
}

size_t mbedcrypto_bn_byte_count(const struct mbedcrypto_bignum *X)
{
	return (mbedcrypto_bn_bit_count(X) + 7) / 8;
}

int mbedcrypto_bn_test_bit(const struct mbedcrypto_bignum *X, size_t pos)
{
	size_t wi = pos / BN_WORD_BITS;
	size_t bit = pos % BN_WORD_BITS;

	if (wi >= X->used)
		return 0;

	return (X->data[wi] >> bit) & 1;
}

int mbedcrypto_bn_assign_bit(struct mbedcrypto_bignum *X, size_t pos, int val)
{
	size_t wi = pos / BN_WORD_BITS;
	size_t bit = pos % BN_WORD_BITS;
	int ret = 0;

	if (val != 0 && val != 1)
		return -EINVAL;

	if ((ret = mbedcrypto_bn_expand(X, wi + 1)) != 0)
		return ret;

	X->data[wi] &= ~((bn_word_t)1 << bit);
	X->data[wi] |= ((bn_word_t)val << bit);

	return 0;
}

int mbedcrypto_bn_rshift(struct mbedcrypto_bignum *X, size_t count)
{
	size_t word_shift = count / BN_WORD_BITS;
	size_t bit_shift = count % BN_WORD_BITS;
	size_t i = 0;

	if (word_shift >= X->used) {
		memset(X->data, 0, X->used * sizeof(bn_word_t));
		return 0;
	}

	/* Shift by whole words. */
	if (word_shift > 0) {
		for (i = 0; i < X->used - word_shift; i++)
			X->data[i] = X->data[i + word_shift];
		for (; i < X->used; i++)
			X->data[i] = 0;
	}

	/* Shift by remaining bits. */
	if (bit_shift > 0) {
		for (i = 0; i < X->used - 1; i++)
			X->data[i] = (X->data[i] >> bit_shift) |
				   (X->data[i + 1] << (BN_WORD_BITS - bit_shift));
		X->data[X->used - 1] >>= bit_shift;
	}

	return 0;
}

int mbedcrypto_bn_lshift(struct mbedcrypto_bignum *X, size_t count)
{
	size_t word_shift = count / BN_WORD_BITS;
	size_t bit_shift = count % BN_WORD_BITS;
	size_t i = 0;
	size_t new_n = 0;
	int ret = 0;

	/* Compute required size. */
	i = mbedcrypto_bn_bit_count(X);
	new_n = (i + count + BN_WORD_BITS - 1) / BN_WORD_BITS;

	if ((ret = mbedcrypto_bn_expand(X, new_n)) != 0)
		return ret;

	/* Shift by remaining bits first (to not overwrite data). */
	if (bit_shift > 0) {
		for (i = X->used - 1; i > 0; i--)
			X->data[i] = (X->data[i] << bit_shift) |
				   (X->data[i - 1] >> (BN_WORD_BITS - bit_shift));
		X->data[0] <<= bit_shift;
	}

	/* Shift by whole words. */
	if (word_shift > 0) {
		for (i = X->used; i > word_shift; i--)
			X->data[i - 1] = X->data[i - 1 - word_shift];
		for (i = 0; i < word_shift; i++)
			X->data[i] = 0;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Serialization                                                      */
/* ------------------------------------------------------------------ */

int mbedcrypto_bn_from_binary(struct mbedcrypto_bignum *X,
		const uint8_t *buf, size_t buflen)
{
	int ret = 0;
	size_t nwords = (buflen + BN_WORD_BYTES - 1) /
			BN_WORD_BYTES;
	size_t i = 0;

	if ((ret = mbedcrypto_bn_expand(X, nwords)) != 0)
		return ret;

	memset(X->data, 0, X->used * sizeof(bn_word_t));
	X->neg = 0;

	/* Big-endian to little-endian words. */
	for (i = 0; i < buflen; i++) {
		size_t byte_pos = buflen - 1 - i;
		size_t word_idx = i / BN_WORD_BYTES;
		size_t bit_off = (i % BN_WORD_BYTES) * 8;

		X->data[word_idx] |= ((bn_word_t)buf[byte_pos]) << bit_off;
	}

	return 0;
}

int mbedcrypto_bn_to_binary(const struct mbedcrypto_bignum *X,
		uint8_t *buf, size_t buflen)
{
	size_t stored = mbedcrypto_bn_byte_count(X);
	size_t i = 0;

	if (stored > buflen)
		return -EINVAL;

	memset(buf, 0, buflen);

	/* Little-endian words to big-endian bytes. */
	for (i = 0; i < stored; i++) {
		size_t word_idx = i / BN_WORD_BYTES;
		size_t bit_off = (i % BN_WORD_BYTES) * 8;

		buf[buflen - 1 - i] = X->data[word_idx] >> bit_off;
	}

	return 0;
}

/*
 * Read X from a hex string (e.g. "1A2B3C").
 * The string is parsed as big-endian (most significant nibble first).
 */
int mbedcrypto_bn_from_hex(struct mbedcrypto_bignum *X, const char *hex)
{
	size_t len = strlen(hex);
	size_t nbytes = (len + 1) / 2;
	uint8_t *buf = NULL;
	int ret = 0;
	size_t i = 0;

	buf = calloc(1, nbytes);
	if (!buf)
		return -ENOMEM;

	/* Parse hex pairs from the end */
	for (i = 0; i < len; i++) {
		uint8_t c = 0;
		char ch = hex[len - 1 - i];

		if (ch >= '0' && ch <= '9')      c = ch - '0';
		else if (ch >= 'a' && ch <= 'f') c = ch - 'a' + 10;
		else if (ch >= 'A' && ch <= 'F') c = ch - 'A' + 10;
		else { free(buf); return -EINVAL; }

		buf[nbytes - 1 - i / 2] |= c << ((i & 1) * 4);
	}

	ret = mbedcrypto_bn_from_binary(X, buf, nbytes);
	free(buf);
	return ret;
}

int mbedcrypto_bn_from_binary_le(struct mbedcrypto_bignum *X,
		const uint8_t *buf, size_t buflen)
{
	int ret = 0;
	size_t nwords = (buflen + BN_WORD_BYTES - 1) /
			BN_WORD_BYTES;
	size_t i = 0;

	if ((ret = mbedcrypto_bn_expand(X, nwords)) != 0)
		return ret;

	memset(X->data, 0, X->used * sizeof(bn_word_t));
	X->neg = 0;

	/* Little-endian bytes to little-endian words. */
	for (i = 0; i < buflen; i++) {
		size_t word_idx = i / BN_WORD_BYTES;
		size_t bit_off = (i % BN_WORD_BYTES) * 8;

		X->data[word_idx] |= ((bn_word_t)buf[i]) << bit_off;
	}

	return 0;
}

int mbedcrypto_bn_to_binary_le(const struct mbedcrypto_bignum *X,
		uint8_t *buf, size_t buflen)
{
	size_t stored = mbedcrypto_bn_byte_count(X);
	size_t i = 0;

	if (stored > buflen)
		return -EINVAL;

	memset(buf, 0, buflen);

	/* Little-endian words to little-endian bytes. */
	for (i = 0; i < stored; i++) {
		size_t word_idx = i / BN_WORD_BYTES;
		size_t bit_off = (i % BN_WORD_BYTES) * 8;

		buf[i] = X->data[word_idx] >> bit_off;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Comparison                                                         */
/* ------------------------------------------------------------------ */

int mbedcrypto_bn_cmp_magnitude(const struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *Y)
{
	size_t i = 0;

	/* Find actual sizes. */
	size_t xi = X->used, yi = Y->used;

	while (xi > 0 && X->data[xi - 1] == 0) xi--;
	while (yi > 0 && Y->data[yi - 1] == 0) yi--;

	if (xi > yi)
		return 1;
	if (xi < yi)
		return -1;

	for (i = xi; i > 0; i--) {
		if (X->data[i - 1] > Y->data[i - 1])
			return 1;
		if (X->data[i - 1] < Y->data[i - 1])
			return -1;
	}

	return 0;
}

int mbedcrypto_bn_cmp(const struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *Y)
{
	size_t xi = X->used, yi = Y->used;
	int r = 0;

	while (xi > 0 && X->data[xi - 1] == 0) xi--;
	while (yi > 0 && Y->data[yi - 1] == 0) yi--;

	/* Both zero. */
	if (xi == 0 && yi == 0)
		return 0;

	if (!X->neg && Y->neg)
		return 1;
	if (X->neg && !Y->neg)
		return -1;

	r = mbedcrypto_bn_cmp_magnitude(X, Y);

	/* If negative, comparison is reversed. */
	if (X->neg)
		r = -r;

	return r;
}

int mbedcrypto_bn_cmp_word(const struct mbedcrypto_bignum *X, int z)
{
	struct mbedcrypto_bignum Y;
	bn_word_t val;

	/* See mbedcrypto_bn_set_word for |z| computation rationale */
	val = (z < 0) ? (bn_word_t)0 - (bn_word_t)z : (bn_word_t)z;

	Y.neg = (z < 0);
	Y.used = 1;
	Y.capacity = 0;
	Y.data = &val;

	return mbedcrypto_bn_cmp(X, &Y);
}

/* ------------------------------------------------------------------ */
/*  Unsigned add / sub helpers                                         */
/* ------------------------------------------------------------------ */

/*
 * dst[0..len-1] = a[0..len-1] + b[0..len-1] + carry_in.
 * Returns carry out (0 or 1).
 *
 * On x86-64, uses a native adc chain (dec preserves CF, enabling
 * a tight carry-propagation loop without explicit carry tracking).
 */
static bn_word_t bn_add_chain(bn_word_t *dst,
		const bn_word_t *a, const bn_word_t *b,
		size_t len, bn_word_t carry)
{
	if (len == 0)
		return carry;

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
	__asm__ volatile (
		"negq %[cy]\n\t"          /* CF = (carry != 0) */
		".p2align 4\n"
		"1:\n\t"
		"movq (%[av]), %%rax\n\t"
		"adcq (%[bv]), %%rax\n\t"
		"movq %%rax, (%[dv])\n\t"
		"leaq 8(%[av]), %[av]\n\t"
		"leaq 8(%[bv]), %[bv]\n\t"
		"leaq 8(%[dv]), %[dv]\n\t"
		"decq %[n]\n\t"
		"jnz 1b\n\t"
		"adcq %[n], %[cy]"        /* cy = 0 + CF (n is 0 here) */
		: [av] "+r"(a), [bv] "+r"(b), [dv] "+r"(dst),
		  [n] "+r"(len), [cy] "+r"(carry)
		:
		: "cc", "memory", "rax"
	);
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
	__asm__ volatile (
		/* cmp sets C=0 when carry==0, C=1 when carry==1 */
		"cmp %[cy], #1\n\t"
		"1:\n\t"
		"ldr x9, [%[av]], #8\n\t"
		"ldr x10, [%[bv]], #8\n\t"
		"adcs x9, x9, x10\n\t"
		"str x9, [%[dv]], #8\n\t"
		"sub %[n], %[n], #1\n\t"
		"cbnz %[n], 1b\n\t"
		"adc %[cy], xzr, xzr"
		: [av] "+r"(a), [bv] "+r"(b), [dv] "+r"(dst),
		  [n] "+r"(len), [cy] "+r"(carry)
		:
		: "cc", "memory", "x9", "x10"
	);
#elif defined(__arm__) && !defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
	__asm__ volatile (
		/* cmp sets C=0 when carry==0, C=1 when carry!=0 */
		"cmp %[cy], #1\n\t"
		"1:\n\t"
		"ldr r4, [%[av]], #4\n\t"
		"ldr r5, [%[bv]], #4\n\t"
		"adcs r4, r4, r5\n\t"
		"str r4, [%[dv]], #4\n\t"
		"sub %[n], %[n], #1\n\t"
		"teq %[n], #0\n\t"      /* teq does not modify C flag */
		"bne 1b\n\t"
		"adc %[cy], %[n], #0"   /* n is 0, so cy = 0 + C */
		: [av] "+r"(a), [bv] "+r"(b), [dv] "+r"(dst),
		  [n] "+r"(len), [cy] "+r"(carry)
		:
		: "cc", "memory", "r4", "r5"
	);
#else
	size_t i = 0;
	for (i = 0; i < len; i++) {
		bn_word_t s = a[i] + carry;
		bn_word_t c1 = (s < a[i]) ? 1 : 0;
		bn_word_t t = s + b[i];
		bn_word_t c2 = (t < s) ? 1 : 0;

		dst[i] = t;
		carry = c1 + c2;
	}
#endif
	return carry;
}

/*
 * dst[0..len-1] = a[0..len-1] - b[0..len-1] - borrow_in.
 * Returns borrow out (0 or 1).
 */
static bn_word_t bn_sub_chain(bn_word_t *dst,
		const bn_word_t *a, const bn_word_t *b,
		size_t len, bn_word_t borrow)
{
	if (len == 0)
		return borrow;

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
	__asm__ volatile (
		/* Set CF from borrow input */
		"negq %[bw]\n\t"          /* CF = (borrow != 0) */
		".p2align 4\n"
		"1:\n\t"
		"movq (%[av]), %%rax\n\t"
		"sbbq (%[bv]), %%rax\n\t"
		"movq %%rax, (%[dv])\n\t"
		"leaq 8(%[av]), %[av]\n\t"
		"leaq 8(%[bv]), %[bv]\n\t"
		"leaq 8(%[dv]), %[dv]\n\t"
		"decq %[n]\n\t"
		"jnz 1b\n\t"
		"sbbq %[bw], %[bw]\n\t"
		"negq %[bw]"              /* bw = CF as 0 or 1 */
		: [av] "+r"(a), [bv] "+r"(b), [dv] "+r"(dst),
		  [n] "+r"(len), [bw] "+r"(borrow)
		:
		: "cc", "memory", "rax"
	);
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
	__asm__ volatile (
		/*
		 * AArch64 sbcs uses inverted carry: C=1 no borrow, C=0 borrow.
		 * negs sets C=1 when borrow==0, C=0 when borrow==1.
		 */
		"negs %[bw], %[bw]\n\t"
		"1:\n\t"
		"ldr x9, [%[av]], #8\n\t"
		"ldr x10, [%[bv]], #8\n\t"
		"sbcs x9, x9, x10\n\t"
		"str x9, [%[dv]], #8\n\t"
		"sub %[n], %[n], #1\n\t"
		"cbnz %[n], 1b\n\t"
		"cset %[bw], cc"     /* borrow out = inverted C flag */
		: [av] "+r"(a), [bv] "+r"(b), [dv] "+r"(dst),
		  [n] "+r"(len), [bw] "+r"(borrow)
		:
		: "cc", "memory", "x9", "x10"
	);
#elif defined(__arm__) && !defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
	__asm__ volatile (
		/*
		 * ARM32 sbcs: C=0 means borrow, C=1 means no borrow.
		 * rsbs sets C=1 when borrow==0, C=0 when borrow!=0.
		 */
		"rsbs %[bw], %[bw], #0\n\t"
		"1:\n\t"
		"ldr r4, [%[av]], #4\n\t"
		"ldr r5, [%[bv]], #4\n\t"
		"sbcs r4, r4, r5\n\t"
		"str r4, [%[dv]], #4\n\t"
		"sub %[n], %[n], #1\n\t"
		"teq %[n], #0\n\t"      /* teq does not modify C flag */
		"bne 1b\n\t"
		"sbc %[bw], %[n], #0\n\t" /* bw = 0 - 0 - !C = -1 or 0 */
		"rsb %[bw], %[bw], #0"     /* negate: bw = 0 or 1 */
		: [av] "+r"(a), [bv] "+r"(b), [dv] "+r"(dst),
		  [n] "+r"(len), [bw] "+r"(borrow)
		:
		: "cc", "memory", "r4", "r5"
	);
#else
	size_t i = 0;

	for (i = 0; i < len; i++) {
		bn_word_t t = a[i] - borrow;
		bn_word_t c1 = (t > a[i]) ? 1 : 0;
		bn_word_t s = t - b[i];
		bn_word_t c2 = (s > t) ? 1 : 0;

		dst[i] = s;
		borrow = c1 + c2;
	}
#endif
	return borrow;
}

/* X = |A| + |B| (unsigned, called internally). */
static int bn_add_abs(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B)
{
	int ret = 0;
	size_t i = 0, mn = 0, n = 0;
	size_t an = 0, bn = 0;
	bn_word_t carry = 0;

	/* Trim leading zeros to avoid over-allocating. */
	for (an = A->used; an > 0 && A->data[an - 1] == 0; an--);
	for (bn = B->used; bn > 0 && B->data[bn - 1] == 0; bn--);
	n = (an > bn) ? an : bn;
	mn = (an < bn) ? an : bn;

	if ((ret = mbedcrypto_bn_expand(X, n + 1)) != 0)
		return ret;

	/*
	 * Phase 1: both A and B contribute (overlap region).
	 * Phase 2: only the longer operand contributes.
	 */
	carry = bn_add_chain(X->data, A->data, B->data, mn, 0);

	for (i = mn; i < n; i++) {
		bn_word_t v = (i < an) ? A->data[i] : B->data[i];
		bn_word_t s = v + carry;

		carry = (s < v) ? 1 : 0;
		X->data[i] = s;
	}

	if (carry != 0)
		X->data[n++] = carry;

	/* Zero remaining. */
	for (i = n; i < X->used; i++)
		X->data[i] = 0;

	return 0;
}

/*
 * X = |A| - |B| (unsigned, |A| >= |B| assumed).
 * Returns -EINVAL if |A| < |B|.
 */
static int bn_sub_abs(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B)
{
	int ret = 0;
	size_t i = 0, n = 0, bn = 0;
	bn_word_t borrow = 0;

	n = A->used;
	bn = B->used;
	if (bn > n)
		bn = n;

	if ((ret = mbedcrypto_bn_expand(X, n)) != 0)
		return ret;

	/* Phase 1: both A and B contribute (overlap region). */
	borrow = bn_sub_chain(X->data, A->data, B->data, bn, 0);

	/* Phase 2: propagate borrow through remaining A words. */
	for (i = bn; i < n; i++) {
		bn_word_t a = A->data[i];
		bn_word_t t = a - borrow;

		borrow = (t > a) ? 1 : 0;
		X->data[i] = t;
	}

	if (borrow != 0)
		return -EINVAL;

	/* Zero remaining. */
	for (; i < X->used; i++)
		X->data[i] = 0;

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Signed arithmetic                                                  */
/* ------------------------------------------------------------------ */

int mbedcrypto_bn_add(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B)
{
	int ret = 0;

	if ((A->neg != B->neg)) {
		/* Different signs: subtraction. */
		int cmp = mbedcrypto_bn_cmp_magnitude(A, B);

		if (cmp >= 0) {
			ret = bn_sub_abs(X, A, B);
			X->neg = A->neg;
		} else {
			ret = bn_sub_abs(X, B, A);
			X->neg = B->neg;
		}

		/* Handle -0. */
		if (mbedcrypto_bn_bit_count(X) == 0)
			X->neg = 0;
	} else {
		/* Same signs: addition. */
		ret = bn_add_abs(X, A, B);
		X->neg = A->neg;
	}

	return ret;
}

int mbedcrypto_bn_sub(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B)
{
	/*
	 * X = A - B.
	 * Implemented inline rather than via bn_add with a negated
	 * shallow copy, because the shallow copy NB = *B shares the
	 * data pointer and bn_grow(X) can realloc when X aliases B,
	 * leaving NB.data dangling (use-after-free).
	 */
	int ret = 0;
	int b_neg = !B->neg; /* treat B as negated */

	if ((A->neg != b_neg)) {
		/* Different signs: subtraction of magnitudes. */
		int cmp = mbedcrypto_bn_cmp_magnitude(A, B);

		if (cmp >= 0) {
			ret = bn_sub_abs(X, A, B);
			X->neg = A->neg;
		} else {
			ret = bn_sub_abs(X, B, A);
			X->neg = b_neg;
		}

		/* Handle -0. */
		if (mbedcrypto_bn_bit_count(X) == 0)
			X->neg = 0;
	} else {
		/* Same signs: addition of magnitudes. */
		ret = bn_add_abs(X, A, B);
		X->neg = A->neg;
	}

	return ret;
}

int mbedcrypto_bn_add_word(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A, int b)
{
	struct mbedcrypto_bignum B;
	bn_word_t val;

	/* See mbedcrypto_bn_set_word for |b| computation rationale */
	val = (b < 0) ? (bn_word_t)0 - (bn_word_t)b : (bn_word_t)b;

	B.neg = (b < 0);
	B.used = 1;
	B.capacity = 0;
	B.data = &val;

	return mbedcrypto_bn_add(X, A, &B);
}

/* ------------------------------------------------------------------ */
/*  Multiply-accumulate (platform-optimized inner loop)                */
/* ------------------------------------------------------------------ */

/*
 * dst[0..len-1] += src[0..len-1] * scalar.
 * Returns the carry word.
 *
 * This is the hot path for schoolbook and Montgomery multiplication.
 * Platform-specific assembly avoids double-width arithmetic overhead
 * and keeps carry propagation in registers.
 */
static bn_word_t bn_madd(bn_word_t *dst,
		const bn_word_t *src, size_t len,
		bn_word_t scalar)
{
	bn_word_t carry = 0;
	size_t i = 0;

/*
 * Inline assembly requires GCC or Clang (both define __GNUC__).
 * The check is for compiler feature support, not for the GNU project.
 */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
	for (i = 0; i < len; i++) {
		bn_word_t lo = 0, hi = 0;

		__asm__ ("mulq %[sc]\n\t"
			 "addq %[cy], %%rax\n\t"
			 "adcq $0, %%rdx\n\t"
			 "addq %[dv], %%rax\n\t"
			 "adcq $0, %%rdx"
			 : "=a"(lo), "=&d"(hi)
			 : "a"(src[i]), [sc] "rm"(scalar),
			   [cy] "rm"(carry), [dv] "rm"(dst[i])
			 : "cc");

		dst[i] = lo;
		carry = hi;
	}
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
	for (i = 0; i < len; i++) {
		bn_word_t lo = 0, hi = 0;

		__asm__ ("mul %[lo], %[sv], %[sc]\n\t"
			 "umulh %[hi], %[sv], %[sc]\n\t"
			 "adds %[lo], %[lo], %[cy]\n\t"
			 "adc %[hi], %[hi], xzr\n\t"
			 "adds %[lo], %[lo], %[dv]\n\t"
			 "adc %[hi], %[hi], xzr"
			 : [lo] "=&r"(lo), [hi] "=&r"(hi)
			 : [sv] "r"(src[i]), [sc] "r"(scalar),
			   [cy] "r"(carry), [dv] "r"(dst[i])
			 : "cc");

		dst[i] = lo;
		carry = hi;
	}
#elif defined(__arm__) && !defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
	for (i = 0; i < len; i++) {
		bn_word_t lo = 0, hi = 0;

		__asm__ ("umull %[lo], %[hi], %[sv], %[sc]\n\t"
			 "adds %[lo], %[lo], %[cy]\n\t"
			 "adc %[hi], %[hi], #0\n\t"
			 "adds %[lo], %[lo], %[dv]\n\t"
			 "adc %[hi], %[hi], #0"
			 : [lo] "=&r"(lo), [hi] "=&r"(hi)
			 : [sv] "r"(src[i]), [sc] "r"(scalar),
			   [cy] "r"(carry), [dv] "r"(dst[i])
			 : "cc");

		dst[i] = lo;
		carry = hi;
	}
#else
	/* Portable C fallback using double-width arithmetic. */
	for (i = 0; i < len; i++) {
		bn_dword_t prod = (bn_dword_t)src[i] * scalar +
					  dst[i] + carry;

		dst[i] = (bn_word_t)prod;
		carry = (bn_word_t)(prod >> BN_WORD_BITS);
	}
#endif

	return carry;
}

/* ------------------------------------------------------------------ */
/*  Multiplication                                                     */
/* ------------------------------------------------------------------ */

int mbedcrypto_bn_mul(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B)
{
	int ret = 0;
	size_t i = 0;
	size_t an = 0, bn = 0;
	struct mbedcrypto_bignum T;

	/* Find actual sizes. */
	for (an = A->used; an > 0 && A->data[an - 1] == 0; an--);
	for (bn = B->used; bn > 0 && B->data[bn - 1] == 0; bn--);

	mbedcrypto_bn_init(&T);

	if ((ret = mbedcrypto_bn_expand(&T, an + bn)) != 0)
		goto out;

	memset(T.data, 0, T.used * sizeof(bn_word_t));

	for (i = 0; i < an; i++)
		T.data[i + bn] += bn_madd(T.data + i, B->data, bn, A->data[i]);

	T.neg = A->neg ^ B->neg;

	mbedcrypto_bn_swap(X, &T);

out:
	mbedcrypto_bn_cleanup(&T);

	return ret;
}

/*
 * X = A * B, using caller-provided temp T for the product buffer.
 * T must be pre-allocated (via bn_grow); it is NOT freed.
 */
int mbedcrypto_bn_mul_karatsuba(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B,
		struct mbedcrypto_bignum *T)
{
	size_t i = 0;
	size_t an = 0, bn = 0;
	int ret = 0;

	for (an = A->used; an > 0 && A->data[an - 1] == 0; an--);
	for (bn = B->used; bn > 0 && B->data[bn - 1] == 0; bn--);

	if ((ret = mbedcrypto_bn_expand(T, an + bn)) != 0)
		return ret;

	memset(T->data, 0, T->used * sizeof(bn_word_t));

	for (i = 0; i < an; i++)
		T->data[i + bn] += bn_madd(T->data + i, B->data, bn,
					   A->data[i]);

	T->neg = A->neg ^ B->neg;

	mbedcrypto_bn_swap(X, T);

	return 0;
}

int mbedcrypto_bn_mul_word(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		bn_word_t b)
{
	struct mbedcrypto_bignum B;

	B.neg = 0;
	B.used = 1;
	B.capacity = 0;
	B.data = &b;

	return mbedcrypto_bn_mul(X, A, &B);
}

/* ------------------------------------------------------------------ */
/*  Division (Knuth Algorithm D - word-by-word long division)          */
/* ------------------------------------------------------------------ */

/*
 * Helper: subtract q * d[0..dlen-1] from u[j..j+dlen], return borrow.
 * This is the core "multiply-and-subtract" step of long division.
 */
static bn_word_t bn_div_msub(bn_word_t *u,
		const bn_word_t *d, size_t dlen,
		bn_word_t q, size_t j)
{
	bn_word_t carry = 0;
	size_t i = 0;

	for (i = 0; i < dlen; i++) {
		bn_dword_t prod = (bn_dword_t)d[i] * q + carry;
		bn_word_t lo = (bn_word_t)prod;
		carry = (bn_word_t)(prod >> BN_WORD_BITS);

		if (u[j + i] < lo)
			carry++;
		u[j + i] -= lo;
	}

	/* Propagate borrow into u[j + dlen] */
	if (u[j + dlen] < carry) {
		u[j + dlen] -= carry;
		return 1; /* borrow */
	}
	u[j + dlen] -= carry;
	return 0;
}

/*
 * Helper: add back d[0..dlen-1] to u[j..j+dlen-1] (compensate step).
 * Used when trial quotient was one too large.
 */
static void bn_div_addback(bn_word_t *u,
		const bn_word_t *d, size_t dlen, size_t j)
{
	bn_word_t carry = 0;
	size_t i = 0;

	for (i = 0; i < dlen; i++) {
		bn_dword_t sum = (bn_dword_t)u[j + i] + d[i] + carry;
		u[j + i] = (bn_word_t)sum;
		carry = (bn_word_t)(sum >> BN_WORD_BITS);
	}
	u[j + dlen] += carry;
}

int mbedcrypto_bn_div(struct mbedcrypto_bignum *Q,
		struct mbedcrypto_bignum *R,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B)
{
	int ret = 0;
	int a_neg = 0, b_neg = 0;
	size_t m = 0, n = 0, i = 0;
	unsigned int shift = 0;
	struct mbedcrypto_bignum U, D;
	bn_word_t *qp = NULL;

	if (mbedcrypto_bn_cmp_word(B, 0) == 0)
		return -EINVAL;

	a_neg = A->neg;
	b_neg = B->neg;

	mbedcrypto_bn_init(&U);
	mbedcrypto_bn_init(&D);

	/* Work with absolute values */
	if ((ret = mbedcrypto_bn_copy(&U, A)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_copy(&D, B)) != 0)
		goto cleanup;
	U.neg = 0;
	D.neg = 0;

	if (mbedcrypto_bn_cmp_magnitude(&U, &D) < 0) {
		if (Q) {
			if ((ret = mbedcrypto_bn_set_word(Q, 0)) != 0)
				goto cleanup;
		}
		if (R) {
			if ((ret = mbedcrypto_bn_copy(R, &U)) != 0)
				goto cleanup;
			R->neg = a_neg;
		}
		goto cleanup;
	}

	/* Find actual word counts (strip leading zeros) */
	for (n = D.used; n > 0 && D.data[n - 1] == 0; n--);
	for (m = U.used; m > 0 && U.data[m - 1] == 0; m--);

	/* Single-word divisor: use simple loop */
	if (n == 1) {
		bn_word_t d0 = D.data[0];
		bn_word_t rem = 0;

		if (Q) {
			if ((ret = mbedcrypto_bn_expand(Q, m)) != 0)
				goto cleanup;
			memset(Q->data, 0, Q->used * sizeof(bn_word_t));
		}

		for (i = m; i > 0; i--) {
			bn_dword_t tmp = ((bn_dword_t)rem
				<< BN_WORD_BITS) | U.data[i - 1];
			if (Q)
				Q->data[i - 1] = (bn_word_t)(tmp / d0);
			rem = (bn_word_t)(tmp % d0);
		}

		if (Q)
			Q->neg = a_neg ^ b_neg;
		if (R) {
			if ((ret = mbedcrypto_bn_expand(R, 1)) != 0)
				goto cleanup;
			memset(R->data, 0,
			       R->used * sizeof(bn_word_t));
			R->data[0] = rem;
			R->neg = a_neg;
			if (rem == 0)
				R->neg = 0;
		}
		goto cleanup;
	}

	/*
	 * Multi-word divisor: Knuth Algorithm D.
	 *
	 * Normalize: shift D left so its MSB is set. Apply same shift to U.
	 * This ensures the trial quotient estimate is accurate within 1.
	 */
	shift = bn_clz(D.data[n - 1]);
	if (shift > 0) {
		if ((ret = mbedcrypto_bn_lshift(&D, shift)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_lshift(&U, shift)) != 0)
			goto cleanup;
	}

	/* Ensure U has m - n + 1 quotient words worth of space plus n */
	if (m < n)
		m = n;
	if ((ret = mbedcrypto_bn_expand(&U, m + 1)) != 0)
		goto cleanup;

	/* Allocate quotient words */
	if (Q) {
		qp = calloc(m - n + 1, sizeof(bn_word_t));
		if (!qp) {
			ret = -ENOMEM;
			goto cleanup;
		}
	}

	/* Main loop: for each quotient word j = m-n down to 0 */
	for (i = m - n + 1; i > 0; i--) {
		size_t j = i - 1;
		bn_dword_t qhat = 0, rhat = 0;
		bn_word_t q_est = 0;

		/*
		 * Trial quotient: qhat = (u[j+n]*b + u[j+n-1]) / d[n-1]
		 * where b = 2^BN_WORD_BITS.
		 */
		qhat = ((bn_dword_t)U.data[j + n]
			<< BN_WORD_BITS) | U.data[j + n - 1];
		rhat = qhat % D.data[n - 1];
		qhat /= D.data[n - 1];

		/*
		 * Knuth step D3: refine trial quotient.
		 * Without this, qhat may exceed q by 2.
		 * After refinement, qhat <= q + 1.
		 */
		while (qhat > (bn_dword_t)(bn_word_t)~0ULL ||
		       (n >= 2 &&
			qhat * D.data[n - 2] >
			((rhat << BN_WORD_BITS) |
			 U.data[j + n - 2]))) {
			qhat--;
			rhat += D.data[n - 1];
			if (rhat >> BN_WORD_BITS)
				break;
		}
		q_est = (bn_word_t)qhat;

		/*
		 * Multiply and subtract: u[j..j+n] -= q_est * d[0..n-1].
		 * If result is negative (borrow), q_est was too large by 1:
		 * add back d and decrement q_est.
		 */
		if (bn_div_msub(U.data, D.data, n, q_est, j)) {
			bn_div_addback(U.data, D.data, n, j);
			q_est--;
		}

		if (qp)
			qp[j] = q_est;
	}

	if (Q) {
		Q->neg = a_neg ^ b_neg;
		free(Q->data);
		Q->data = qp;
		Q->used = m - n + 1;
		Q->capacity = m - n + 1;
		qp = NULL;
		if (mbedcrypto_bn_bit_count(Q) == 0)
			Q->neg = 0;
	}

	if (R) {
		/* Unnormalize: shift remainder right by 'shift' bits */
		if ((ret = mbedcrypto_bn_copy(R, &U)) != 0)
			goto cleanup;
		if (shift > 0) {
			if ((ret = mbedcrypto_bn_rshift(R, shift)) != 0)
				goto cleanup;
		}
		R->neg = a_neg;
		if (mbedcrypto_bn_bit_count(R) == 0)
			R->neg = 0;
	}

cleanup:
	free(qp);
	mbedcrypto_bn_cleanup(&U);
	mbedcrypto_bn_cleanup(&D);
	return ret;
}

int mbedcrypto_bn_mod(struct mbedcrypto_bignum *R,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B)
{
	int ret = 0;

	if (mbedcrypto_bn_cmp_word(B, 0) <= 0)
		return -EINVAL;

	if ((ret = mbedcrypto_bn_div(NULL, R, A, B)) != 0)
		return ret;

	if (R->neg) {
		if ((ret = mbedcrypto_bn_add(R, R, B)) != 0)
			return ret;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Montgomery multiplication                                          */
/* ------------------------------------------------------------------ */

/*
 * Compute Montgomery constant: mm = -N^(-1) mod 2^BN_WORD_BITS.
 * N must be odd.
 */
static bn_word_t bn_montg_init(const struct mbedcrypto_bignum *N)
{
	bn_word_t x = N->data[0];
	bn_word_t m = 0;

	/* Newton's method to compute -N^(-1) mod 2^BN_WORD_BITS. */
	m = 2 - x;
	m *= 2 - x * m;  /* 4 bits */
	m *= 2 - x * m;  /* 8 bits */
	m *= 2 - x * m;  /* 16 bits */
	m *= 2 - x * m;  /* 32 bits */
#if BN_WORD_BITS == 64
	m *= 2 - x * m;  /* 64 bits */
#endif

	return ~m + 1; /* -N^(-1) mod 2^BN_WORD_BITS */
}

/*
 * Montgomery multiplication: A = A * B * R^(-1) mod N (in-place on A).
 * d is a temporary of size 2*(n+1), mm = -N^(-1) mod 2^BN_WORD_BITS.
 * n is the number of words in N.
 */
static void bn_montmul(struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B,
		const struct mbedcrypto_bignum *N,
		bn_word_t mm,
		bn_word_t *d, size_t n)
{
	size_t i = 0, j = 0;
	bn_word_t c = 0;
	size_t blen = (B->used < n) ? B->used : n;

	memset(d, 0, (2 * n + 2) * sizeof(bn_word_t));

	for (i = 0; i < n; i++) {
		/* Step 1: d += B * A[i] */
		bn_word_t ai = (i < A->used) ? A->data[i] : 0;
		bn_word_t u = 0;

		if (ai) {
			c = bn_madd(d + i, B->data, blen, ai);
			for (j = i + blen; c != 0; j++) {
				bn_dword_t sum = (bn_dword_t)d[j] + c;

				d[j] = (bn_word_t)sum;
				c = (bn_word_t)(sum >> BN_WORD_BITS);
			}
		}

		/* Step 2: Montgomery reduction - d += N * (d[i] * mm) */
		u = d[i] * mm;

		c = bn_madd(d + i, N->data, n, u);
		for (j = i + n; c != 0; j++) {
			bn_dword_t sum = (bn_dword_t)d[j] + c;

			d[j] = (bn_word_t)sum;
			c = (bn_word_t)(sum >> BN_WORD_BITS);
		}
	}

	/* Result is in d[n..2n]. Copy n+1 words to A (includes carry). */
	for (i = 0; i < n + 1; i++)
		A->data[i] = d[n + i];

	/* Zero remaining words. */
	for (; i < A->used; i++)
		A->data[i] = 0;

	/* If A >= N, subtract N. */
	if (mbedcrypto_bn_cmp_magnitude(A, N) >= 0)
		bn_sub_abs(A, A, N);
}

/*
 * Constant-time fixed-window Montgomery exponentiation: X = A^E mod N.
 *
 * Uses a fixed-size window to process exponent bits in constant time.
 * Precomputes W[0..2^w-1] = A^i in Montgomery form, then for each
 * w-bit window: square w times, CT-select from the table, multiply.
 * No branch depends on the exponent value.
 */
int mbedcrypto_bn_modpow(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *E,
		const struct mbedcrypto_bignum *N,
		struct mbedcrypto_bignum *RR)
{
	int ret = 0;
	size_t i = 0, j = 0, nbits = 0, wsize = 0;
	size_t n;		/* words in N */
	size_t tblsize = 0;
	size_t wval = 0, s = 0, diff = 0, is_zero = 0;
	bn_word_t mm = 0;
	bn_word_t *d = NULL;
	bn_word_t mask = 0;
	struct mbedcrypto_bignum RRi, T, W[64];

	if (mbedcrypto_bn_cmp_word(N, 0) <= 0 || (N->data[0] & 1) == 0)
		return -EINVAL;

	if (mbedcrypto_bn_cmp_word(E, 0) < 0)
		return -EINVAL;

	if (mbedcrypto_bn_cmp_word(E, 0) == 0) {
		ret = mbedcrypto_bn_set_word(X, 1);
		return ret;
	}

	n = N->used;
	nbits = mbedcrypto_bn_bit_count(E);

	/* Choose window size (same thresholds as original). */
	if (nbits > 671) wsize = 6;
	else if (nbits > 239) wsize = 5;
	else if (nbits > 79) wsize = 4;
	else wsize = 3;

	tblsize = (size_t)1 << wsize;
	if (tblsize > 64)
		tblsize = 64;

	/* Initialize table entries. */
	for (i = 0; i < tblsize; i++)
		mbedcrypto_bn_init(&W[i]);
	mbedcrypto_bn_init(&RRi);
	mbedcrypto_bn_init(&T);

	/* Montgomery constant. */
	mm = bn_montg_init(N);

	/* Scratch space for Montgomery multiplication. */
	d = calloc(2 * n + 2, sizeof(bn_word_t));
	if (!d) {
		ret = -ENOMEM;
		goto cleanup;
	}

	/* Compute R^2 mod N (or reuse if provided). */
	if (RR && RR->data)
		ret = mbedcrypto_bn_copy(&RRi, RR);
	else {
		if ((ret = mbedcrypto_bn_set_word(&RRi, 1)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_lshift(&RRi, 2 * n * BN_WORD_BITS)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_mod(&RRi, &RRi, N)) != 0)
			goto cleanup;

		if (RR) {
			if ((ret = mbedcrypto_bn_copy(RR, &RRi)) != 0)
				goto cleanup;
		}
	}

	/* W[0] = R mod N (Montgomery form of 1). */
	if ((ret = mbedcrypto_bn_set_word(&W[0], 1)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_expand(&W[0], n + 1)) != 0)
		goto cleanup;
	bn_montmul(&W[0], &RRi, N, mm, d, n);

	/* W[1] = A * R mod N (Montgomery form of A). */
	if ((ret = mbedcrypto_bn_copy(&W[1], A)) != 0)
		goto cleanup;
	if (mbedcrypto_bn_cmp_magnitude(&W[1], N) >= 0) {
		if ((ret = mbedcrypto_bn_mod(&W[1], &W[1], N)) != 0)
			goto cleanup;
	}
	if ((ret = mbedcrypto_bn_expand(&W[1], n + 1)) != 0)
		goto cleanup;
	bn_montmul(&W[1], &RRi, N, mm, d, n);

	/* W[i] = W[i-1] * W[1] for i = 2..tblsize-1. */
	for (i = 2; i < tblsize; i++) {
		if ((ret = mbedcrypto_bn_copy(&W[i], &W[i - 1])) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_expand(&W[i], n + 1)) != 0)
			goto cleanup;
		bn_montmul(&W[i], &W[1], N, mm, d, n);
	}

	/* X = R mod N (Montgomery form of 1). */
	if ((ret = mbedcrypto_bn_set_word(X, 1)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_expand(X, n + 1)) != 0)
		goto cleanup;
	bn_montmul(X, &RRi, N, mm, d, n);

	/* Scratch for CT-select. */
	if ((ret = mbedcrypto_bn_expand(&T, n + 1)) != 0)
		goto cleanup;

	/*
	 * Constant-time fixed-window exponentiation.
	 *
	 * Pad the exponent to a multiple of wsize bits, then process
	 * each window from MSB to LSB: square wsize times, CT-select
	 * the table entry for the window value, then multiply.
	 *
	 * CT-select iterates ALL table entries using bitwise masking,
	 * so no branch depends on the exponent bits.
	 */
	nbits = ((nbits + wsize - 1) / wsize) * wsize;
	i = nbits;

	while (i > 0) {
		/* Square wsize times. */
		for (s = 0; s < wsize; s++)
			bn_montmul(X, X, N, mm, d, n);

		/* Extract w-bit window value. */
		wval = 0;
		for (s = 0; s < wsize; s++) {
			i--;
			wval = (wval << 1) | (size_t)mbedcrypto_bn_test_bit(E, i);
		}

		/* CT-select: T = W[wval] without branching on wval. */
		memset(T.data, 0, (n + 1) * sizeof(bn_word_t));
		T.used = n + 1;
		for (j = 0; j < tblsize; j++) {
			diff = j ^ wval;
			is_zero = 1 ^ ((diff | (0 - diff)) >>
				(sizeof(size_t) * 8 - 1));
			mask = (bn_word_t)0 - (bn_word_t)is_zero;
			for (s = 0; s <= n; s++)
				T.data[s] |= W[j].data[s] & mask;
		}

		/* X = X * W[wval] */
		bn_montmul(X, &T, N, mm, d, n);
	}

	/* Convert from Montgomery domain: X = X * 1 * R^(-1) mod N. */
	{
		struct mbedcrypto_bignum one;
		bn_word_t one_val = 1;

		one.neg = 0;
		one.used = 1;
		one.capacity = 0;
		one.data = &one_val;

		if ((ret = mbedcrypto_bn_expand(X, n + 1)) != 0)
			goto cleanup;

		bn_montmul(X, &one, N, mm, d, n);
	}

	X->neg = A->neg;

cleanup:
	for (i = 0; i < tblsize; i++)
		mbedcrypto_bn_cleanup(&W[i]);
	mbedcrypto_bn_cleanup(&T);
	mbedcrypto_bn_cleanup(&RRi);
	if (d) {
		memset(d, 0, (2 * n + 2) * sizeof(bn_word_t));
		free(d);
	}

	return ret;
}

/* ------------------------------------------------------------------ */
/*  Binary GCD (Stein's algorithm) - O(n^2)                           */
/* ------------------------------------------------------------------ */

/*
 * Greatest common divisor: G = gcd(A, B).
 * Uses binary GCD (Stein's algorithm) which only needs shifts
 * and subtracts - no division, giving O(n^2) vs O(n^3).
 */
int mbedcrypto_bn_gcd(struct mbedcrypto_bignum *G,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B)
{
	int ret = 0;
	size_t lz = 0, lza = 0, lzb = 0;
	struct mbedcrypto_bignum TA, TB;

	mbedcrypto_bn_init(&TA);
	mbedcrypto_bn_init(&TB);

	if ((ret = mbedcrypto_bn_copy(&TA, A)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_copy(&TB, B)) != 0)
		goto cleanup;
	TA.neg = 0;
	TB.neg = 0;

	/* Handle zero cases */
	if (mbedcrypto_bn_cmp_word(&TA, 0) == 0) {
		ret = mbedcrypto_bn_copy(G, &TB);
		goto cleanup;
	}
	if (mbedcrypto_bn_cmp_word(&TB, 0) == 0) {
		ret = mbedcrypto_bn_copy(G, &TA);
		goto cleanup;
	}

	/* Count and remove common factors of 2 */
	lza = 0;
	while (mbedcrypto_bn_test_bit(&TA, lza) == 0) lza++;
	lzb = 0;
	while (mbedcrypto_bn_test_bit(&TB, lzb) == 0) lzb++;
	lz = (lza < lzb) ? lza : lzb;

	if ((ret = mbedcrypto_bn_rshift(&TA, lza)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_rshift(&TB, lzb)) != 0)
		goto cleanup;

	/* Main loop: both TA and TB are odd */
	while (mbedcrypto_bn_cmp_word(&TA, 0) != 0) {
		/* Remove factors of 2 from TA */
		while (mbedcrypto_bn_test_bit(&TA, 0) == 0) {
			if ((ret = mbedcrypto_bn_rshift(&TA, 1)) != 0)
				goto cleanup;
		}

		/* Remove factors of 2 from TB */
		while (mbedcrypto_bn_test_bit(&TB, 0) == 0) {
			if ((ret = mbedcrypto_bn_rshift(&TB, 1)) != 0)
				goto cleanup;
		}

		/* Ensure TA >= TB, then TA = TA - TB */
		if (mbedcrypto_bn_cmp_magnitude(&TA, &TB) >= 0) {
			if ((ret = bn_sub_abs(&TA, &TA, &TB)) != 0)
				goto cleanup;
		} else {
			if ((ret = bn_sub_abs(&TB, &TB, &TA)) != 0)
				goto cleanup;
		}
	}

	/* Restore common factors of 2 */
	if ((ret = mbedcrypto_bn_copy(G, &TB)) != 0)
		goto cleanup;
	ret = mbedcrypto_bn_lshift(G, lz);

cleanup:
	mbedcrypto_bn_cleanup(&TA);
	mbedcrypto_bn_cleanup(&TB);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Binary Extended GCD for modular inverse                            */
/* ------------------------------------------------------------------ */

/*
 * X = A^(-1) mod N.
 * Uses binary extended GCD (no division needed, O(n^2)).
 * Requires N to be odd (which is always true in crypto:
 * all prime moduli are odd).
 * Falls back to division-based method for even N.
 */
int mbedcrypto_bn_modinv(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *N)
{
	int ret = 0;
	struct mbedcrypto_bignum u, v, x1, x2;

	if (mbedcrypto_bn_cmp_word(A, 0) <= 0 ||
	    mbedcrypto_bn_cmp_word(N, 1) <= 0)
		return -EINVAL;

	/* Binary extended GCD requires odd modulus */
	if (mbedcrypto_bn_test_bit(N, 0) == 0) {
		/* Even N: fall back to division-based extended GCD */
		struct mbedcrypto_bignum G;

		mbedcrypto_bn_init(&G);
		ret = mbedcrypto_bn_egcd(&G, X, NULL, A, N);
		if (ret != 0)
			goto even_out;
		if (mbedcrypto_bn_cmp_word(&G, 1) != 0)
			ret = -EINVAL;
even_out:
		mbedcrypto_bn_cleanup(&G);
		if (ret != 0)
			return ret;

		if (X->neg) {
			ret = mbedcrypto_bn_add(X, X, N);
			if (ret != 0)
				return ret;
		}
		if (mbedcrypto_bn_cmp(X, N) >= 0) {
			ret = mbedcrypto_bn_mod(X, X, N);
			if (ret != 0)
				return ret;
		}
		return 0;
	}

	mbedcrypto_bn_init(&u);
	mbedcrypto_bn_init(&v);
	mbedcrypto_bn_init(&x1);
	mbedcrypto_bn_init(&x2);

	/* u = A mod N, v = N */
	if ((ret = mbedcrypto_bn_mod(&u, A, N)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_copy(&v, N)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_set_word(&x1, 1)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_set_word(&x2, 0)) != 0)
		goto cleanup;

	/*
	 * Binary extended GCD:
	 * Invariant: u * A == x1 (mod N)
	 *            v * A == x2 (mod N)
	 */
	while (mbedcrypto_bn_cmp_word(&u, 1) != 0 &&
	       mbedcrypto_bn_cmp_word(&v, 1) != 0) {

		while (mbedcrypto_bn_test_bit(&u, 0) == 0) {
			if ((ret = mbedcrypto_bn_rshift(&u, 1)) != 0)
				goto cleanup;

			if (mbedcrypto_bn_test_bit(&x1, 0) == 0) {
				if ((ret = mbedcrypto_bn_rshift(&x1, 1)) != 0)
					goto cleanup;
			} else {
				if ((ret = mbedcrypto_bn_add(&x1, &x1, N)) != 0)
					goto cleanup;
				if ((ret = mbedcrypto_bn_rshift(&x1, 1)) != 0)
					goto cleanup;
			}
		}

		while (mbedcrypto_bn_test_bit(&v, 0) == 0) {
			if ((ret = mbedcrypto_bn_rshift(&v, 1)) != 0)
				goto cleanup;

			if (mbedcrypto_bn_test_bit(&x2, 0) == 0) {
				if ((ret = mbedcrypto_bn_rshift(&x2, 1)) != 0)
					goto cleanup;
			} else {
				if ((ret = mbedcrypto_bn_add(&x2, &x2, N)) != 0)
					goto cleanup;
				if ((ret = mbedcrypto_bn_rshift(&x2, 1)) != 0)
					goto cleanup;
			}
		}

		if (mbedcrypto_bn_cmp(&u, &v) >= 0) {
			if ((ret = mbedcrypto_bn_sub(&u, &u, &v)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_sub(&x1, &x1, &x2)) != 0)
				goto cleanup;
		} else {
			if ((ret = mbedcrypto_bn_sub(&v, &v, &u)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_sub(&x2, &x2, &x1)) != 0)
				goto cleanup;
		}
	}

	if (mbedcrypto_bn_cmp_word(&u, 1) == 0)
		ret = mbedcrypto_bn_mod(X, &x1, N);
	else
		ret = mbedcrypto_bn_mod(X, &x2, N);

cleanup:
	mbedcrypto_bn_cleanup(&u);
	mbedcrypto_bn_cleanup(&v);
	mbedcrypto_bn_cleanup(&x1);
	mbedcrypto_bn_cleanup(&x2);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Extended GCD (division-based, kept for API compatibility)          */
/*  gcd -> GCD(x, y) -> u * x + y * v = gcd                           */
/* ------------------------------------------------------------------ */

int mbedcrypto_bn_egcd(struct mbedcrypto_bignum *gcd,
		struct mbedcrypto_bignum *u, struct mbedcrypto_bignum *v,
		const struct mbedcrypto_bignum *x,
		const struct mbedcrypto_bignum *y)
{
	int ret = 0;

	/* Fast path: if neither Bezout coefficient is needed, use binary GCD */
	if (!u && !v)
		return mbedcrypto_bn_gcd(gcd, x, y);

	/* Full extended Euclidean (division-based) for Bezout coefficients */
	{
		struct mbedcrypto_bignum X, Y, A, B, C, D, T, R, TA, TC;

		mbedcrypto_bn_init(&X); mbedcrypto_bn_init(&Y);
		mbedcrypto_bn_init(&A); mbedcrypto_bn_init(&B);
		mbedcrypto_bn_init(&C); mbedcrypto_bn_init(&D);
		mbedcrypto_bn_init(&T); mbedcrypto_bn_init(&R);
		mbedcrypto_bn_init(&TA); mbedcrypto_bn_init(&TC);

		if ((ret = mbedcrypto_bn_copy(&X, x)) != 0)
			goto ext_cleanup;
		if ((ret = mbedcrypto_bn_copy(&Y, y)) != 0)
			goto ext_cleanup;

		X.neg = 0;
		Y.neg = 0;

		if ((ret = mbedcrypto_bn_set_word(&A, 1)) != 0)
			goto ext_cleanup;
		if ((ret = mbedcrypto_bn_set_word(&B, 0)) != 0)
			goto ext_cleanup;
		if ((ret = mbedcrypto_bn_set_word(&C, 0)) != 0)
			goto ext_cleanup;
		if ((ret = mbedcrypto_bn_set_word(&D, 1)) != 0)
			goto ext_cleanup;

		while (mbedcrypto_bn_cmp_word(&X, 0) != 0) {
			if ((ret = mbedcrypto_bn_div(&T, &R, &Y, &X)) != 0)
				goto ext_cleanup;

			if ((ret = mbedcrypto_bn_mul(&TA, &T, &A)) != 0)
				goto ext_cleanup;
			if ((ret = mbedcrypto_bn_sub(&TA, &B, &TA)) != 0)
				goto ext_cleanup;

			if ((ret = mbedcrypto_bn_mul(&TC, &T, &C)) != 0)
				goto ext_cleanup;
			if ((ret = mbedcrypto_bn_sub(&TC, &D, &TC)) != 0)
				goto ext_cleanup;

			mbedcrypto_bn_swap(&B, &A);
			mbedcrypto_bn_swap(&A, &TA);
			mbedcrypto_bn_swap(&D, &C);
			mbedcrypto_bn_swap(&C, &TC);
			mbedcrypto_bn_swap(&Y, &X);
			mbedcrypto_bn_swap(&X, &R);
		}

		if (gcd) {
			if ((ret = mbedcrypto_bn_copy(gcd, &Y)) != 0)
				goto ext_cleanup;
		}

		{
			int x_neg = x->neg;
			int y_neg = y->neg;

			if (u) {
				if ((ret = mbedcrypto_bn_copy(u, &B)) != 0)
					goto ext_cleanup;
				u->neg ^= x_neg;
			}

			if (v) {
				if ((ret = mbedcrypto_bn_copy(v, &D)) != 0)
					goto ext_cleanup;
				v->neg ^= y_neg;
			}
		}

ext_cleanup:
		mbedcrypto_bn_cleanup(&X); mbedcrypto_bn_cleanup(&Y);
		mbedcrypto_bn_cleanup(&A); mbedcrypto_bn_cleanup(&B);
		mbedcrypto_bn_cleanup(&C); mbedcrypto_bn_cleanup(&D);
		mbedcrypto_bn_cleanup(&T); mbedcrypto_bn_cleanup(&R);
		mbedcrypto_bn_cleanup(&TA); mbedcrypto_bn_cleanup(&TC);

		return ret;
	}
}

/* ------------------------------------------------------------------ */
/*  Random fill                                                        */
/* ------------------------------------------------------------------ */

int mbedcrypto_bn_random(struct mbedcrypto_bignum *X, size_t size,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;
	size_t nwords = (size + BN_WORD_BYTES - 1) /
			BN_WORD_BYTES;
	uint8_t *buf = NULL;

	if ((ret = mbedcrypto_bn_expand(X, nwords)) != 0)
		return ret;

	buf = calloc(1, size);
	if (!buf)
		return -ENOMEM;

	ret = f_rng(p_rng, buf, size);
	if (ret != 0) {
		free(buf);
		return ret;
	}

	ret = mbedcrypto_bn_from_binary(X, buf, size);
	memset(buf, 0, size);
	free(buf);

	return ret;
}

/* ------------------------------------------------------------------ */
/*  Primality testing (Miller-Rabin)                                   */
/* ------------------------------------------------------------------ */

static const uint16_t small_primes[] = {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
	47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
	107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163,
	167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
	229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
	283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
	359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
	431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487,
	491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
	571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631,
	641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
	709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773,
	787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857,
	859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
	941, 947, 953, 967, 971, 977, 983, 991, 997, 0
};

static int bn_check_small_factors(const struct mbedcrypto_bignum *X)
{
	struct mbedcrypto_bignum R;
	int ret = 0;
	int i = 0;

	mbedcrypto_bn_init(&R);

	for (i = 0; small_primes[i] != 0; i++) {
		struct mbedcrypto_bignum P;
		bn_word_t pval = (bn_word_t)small_primes[i];

		if (mbedcrypto_bn_cmp_word(X, small_primes[i]) <= 0)
			goto out;

		P.neg = 0;
		P.used = 1;
		P.capacity = 0;
		P.data = &pval;

		ret = mbedcrypto_bn_mod(&R, X, &P);
		if (ret != 0)
			goto out;

		if (mbedcrypto_bn_cmp_word(&R, 0) == 0) {
			ret = -EINVAL;
			goto out;
		}
	}

out:
	mbedcrypto_bn_cleanup(&R);
	return ret;
}

static int bn_miller_rabin(const struct mbedcrypto_bignum *X, int rounds,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;
	int i = 0, j = 0, s = 0;
	struct mbedcrypto_bignum W, R, T, A;
	size_t nbits = 0;
	bn_word_t one_val = 1;

	mbedcrypto_bn_init(&W);
	mbedcrypto_bn_init(&R);
	mbedcrypto_bn_init(&T);
	mbedcrypto_bn_init(&A);

	/* W = X - 1 = 2^s * R, with R odd. */
	{
		struct mbedcrypto_bignum bone;

		bone.neg = 0;
		bone.used = 1;
		bone.capacity = 0;
		bone.data = &one_val;

		if ((ret = mbedcrypto_bn_sub(&W, X, &bone)) != 0)
			goto cleanup;
	}

	/* Find s and R. */
	s = 0;
	if ((ret = mbedcrypto_bn_copy(&R, &W)) != 0)
		goto cleanup;

	while (mbedcrypto_bn_test_bit(&R, 0) == 0) {
		s++;
		if ((ret = mbedcrypto_bn_rshift(&R, 1)) != 0)
			goto cleanup;
	}

	nbits = mbedcrypto_bn_bit_count(X);

	for (i = 0; i < rounds; i++) {
		ret = mbedcrypto_bn_random(&A,
				(nbits + 7) / 8, f_rng, p_rng);
		if (ret != 0)
			goto cleanup;

		if (mbedcrypto_bn_cmp(&A, &W) >= 0) {
			if ((ret = mbedcrypto_bn_mod(&A, &A, &W)) != 0)
				goto cleanup;
		}
		if (mbedcrypto_bn_cmp_word(&A, 2) < 0) {
			if ((ret = mbedcrypto_bn_set_word(&A, 2)) != 0)
				goto cleanup;
		}

		/* T = A^R mod X. */
		if ((ret = mbedcrypto_bn_modpow(&T, &A, &R, X, NULL)) != 0)
			goto cleanup;

		if (mbedcrypto_bn_cmp_word(&T, 1) == 0 ||
		    mbedcrypto_bn_cmp(&T, &W) == 0)
			continue;

		for (j = 1; j < s; j++) {
			bn_word_t two_val = 2;
			struct mbedcrypto_bignum two;

			two.neg = 0;
			two.used = 1;
			two.capacity = 0;
			two.data = &two_val;

			if ((ret = mbedcrypto_bn_modpow(&T, &T, &two, X, NULL)) != 0)
				goto cleanup;

			if (mbedcrypto_bn_cmp_word(&T, 1) == 0) {
				ret = -EINVAL;
				goto cleanup;
			}
			if (mbedcrypto_bn_cmp(&T, &W) == 0)
				break;
		}

		if (j == s) {
			ret = -EINVAL;
			goto cleanup;
		}
	}

	ret = 0;

cleanup:
	mbedcrypto_bn_cleanup(&W);
	mbedcrypto_bn_cleanup(&R);
	mbedcrypto_bn_cleanup(&T);
	mbedcrypto_bn_cleanup(&A);

	return ret;
}

int mbedcrypto_bn_test_prime(const struct mbedcrypto_bignum *X, int rounds,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;

	if (mbedcrypto_bn_cmp_word(X, 0) == 0 ||
	    mbedcrypto_bn_cmp_word(X, 1) == 0)
		return -EINVAL;

	if (mbedcrypto_bn_cmp_word(X, 2) == 0)
		return 0;

	/* Must be odd. */
	if (mbedcrypto_bn_test_bit(X, 0) == 0)
		return -EINVAL;

	if ((ret = bn_check_small_factors(X)) != 0)
		return ret;

	return bn_miller_rabin(X, rounds, f_rng, p_rng);
}

/* ------------------------------------------------------------------ */
/*  Prime generation                                                   */
/* ------------------------------------------------------------------ */

int mbedcrypto_bn_gen_prime(struct mbedcrypto_bignum *X, size_t nbits,
		int flags, mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;
	size_t size = (nbits + 7) / 8;
	struct mbedcrypto_bignum Y;

	if (nbits < 3)
		return -EINVAL;

	mbedcrypto_bn_init(&Y);

	for (;;) {
		if ((ret = mbedcrypto_bn_random(X, size, f_rng, p_rng)) != 0)
			goto cleanup;

		/* Set the top two bits (ensures the number is large enough). */
		if ((ret = mbedcrypto_bn_assign_bit(X, nbits - 1, 1)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_assign_bit(X, nbits - 2, 1)) != 0)
			goto cleanup;

		/* Set bottom bit (ensure odd). */
		X->data[0] |= 1;

		/* Clear bits above nbits. */
		{
			size_t actual = mbedcrypto_bn_bit_count(X);

			while (actual > nbits) {
				if ((ret = mbedcrypto_bn_assign_bit(X, actual - 1, 0)) != 0)
					goto cleanup;
				actual--;
			}
		}

		if (flags & MBEDCRYPTO_BN_GEN_PRIME_FLAG_DH) {
			ret = mbedcrypto_bn_test_prime(X,
					MBEDCRYPTO_BN_PRIME_CHECK_ROUNDS,
					f_rng, p_rng);
			if (ret == -EINVAL)
				continue;
			if (ret != 0)
				goto cleanup;

			if ((ret = mbedcrypto_bn_copy(&Y, X)) != 0)
				goto cleanup;
			if ((ret = mbedcrypto_bn_rshift(&Y, 1)) != 0)
				goto cleanup;

			ret = mbedcrypto_bn_test_prime(&Y,
					MBEDCRYPTO_BN_PRIME_CHECK_ROUNDS,
					f_rng, p_rng);
			if (ret == -EINVAL)
				continue;
			if (ret != 0)
				goto cleanup;

			break;
		}

		ret = mbedcrypto_bn_test_prime(X,
				MBEDCRYPTO_BN_PRIME_CHECK_ROUNDS,
				f_rng, p_rng);
		if (ret == -EINVAL)
			continue;
		if (ret != 0)
			goto cleanup;

		break;
	}

	ret = 0;

cleanup:
	mbedcrypto_bn_cleanup(&Y);

	return ret;
}
