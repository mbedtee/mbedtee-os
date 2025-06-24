/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Big number (arbitrary precision) integer arithmetic
 */

#ifndef _MBEDCRYPTO_BIGNUM_H
#define _MBEDCRYPTO_BIGNUM_H

#include <mbedcrypto/types.h>

/*
 * Adaptive word size: 64-bit on 64-bit platforms for ~2x speedup,
 * 32-bit on 32-bit platforms (ARM32, MIPS32, MicroBlaze).
 * Double-width type used for intermediate multiply results.
 */
#if (defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ >= 8) || \
    defined(__x86_64__) || defined(__aarch64__) || defined(__LP64__) || \
    (defined(__riscv_xlen) && __riscv_xlen == 64)
typedef uint64_t bn_word_t;
typedef __uint128_t bn_dword_t;
#define BN_WORD_BITS  64
#define BN_WORD_BYTES 8
#else
typedef uint32_t bn_word_t;
typedef uint64_t bn_dword_t;
#define BN_WORD_BITS  32
#define BN_WORD_BYTES 4
#endif

/*
 * Big number structure.
 *   neg:      negative flag (0 = positive, 1 = negative)
 *   used:     number of used words
 *   capacity: number of allocated words
 *   data:     pointer to word array (little-endian: data[0] is LSW)
 */
struct mbedcrypto_bignum {
	int neg;
	uint16_t used;
	uint16_t capacity;
	bn_word_t *data;
};

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                         */
/* ------------------------------------------------------------------ */

void mbedcrypto_bn_init(struct mbedcrypto_bignum *X);
void mbedcrypto_bn_cleanup(struct mbedcrypto_bignum *X);

/* Expand capacity to at least 'nwords' words (never shrinks). */
int mbedcrypto_bn_expand(struct mbedcrypto_bignum *X, size_t nwords);

/* Shrink to fit actual data (release trailing zero words). */
int mbedcrypto_bn_shrink(struct mbedcrypto_bignum *X, size_t min);

int mbedcrypto_bn_copy(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *Y);
void mbedcrypto_bn_swap(struct mbedcrypto_bignum *X,
		struct mbedcrypto_bignum *Y);

/* ------------------------------------------------------------------ */
/*  Set / get small values                                            */
/* ------------------------------------------------------------------ */

/* Set X to a signed integer value z. */
int mbedcrypto_bn_set_word(struct mbedcrypto_bignum *X, int z);

/* ------------------------------------------------------------------ */
/*  Bit operations                                                    */
/* ------------------------------------------------------------------ */

/* Return the number of significant bits. */
size_t mbedcrypto_bn_bit_count(const struct mbedcrypto_bignum *X);

/* Return the total size in bytes (ceil(bitlen/8)). */
size_t mbedcrypto_bn_byte_count(const struct mbedcrypto_bignum *X);

/* Get value of bit 'pos' (0 or 1). */
int mbedcrypto_bn_test_bit(const struct mbedcrypto_bignum *X, size_t pos);

/* Assign bit 'pos' to 'val' (0 or 1). */
int mbedcrypto_bn_assign_bit(struct mbedcrypto_bignum *X, size_t pos, int val);

/* Right-shift by 'count' bits. */
int mbedcrypto_bn_rshift(struct mbedcrypto_bignum *X, size_t count);

/* Left-shift by 'count' bits. */
int mbedcrypto_bn_lshift(struct mbedcrypto_bignum *X, size_t count);

/* ------------------------------------------------------------------ */
/*  Serialization (big-endian, unsigned)                              */
/* ------------------------------------------------------------------ */

/* Load X from big-endian binary. Always sets sign to positive. */
int mbedcrypto_bn_from_binary(struct mbedcrypto_bignum *X,
		const uint8_t *buf, size_t buflen);

/* Save X to big-endian binary, zero-padded to 'buflen'. */
int mbedcrypto_bn_to_binary(const struct mbedcrypto_bignum *X,
		uint8_t *buf, size_t buflen);

/* Read X from a hex string (e.g. "1A2B3C"). Always big-endian. */
int mbedcrypto_bn_from_hex(struct mbedcrypto_bignum *X, const char *hex);

/* Load X from little-endian binary. Always sets sign to positive. */
int mbedcrypto_bn_from_binary_le(struct mbedcrypto_bignum *X,
		const uint8_t *buf, size_t buflen);

/* Save X to little-endian binary, zero-padded to 'buflen'. */
int mbedcrypto_bn_to_binary_le(const struct mbedcrypto_bignum *X,
		uint8_t *buf, size_t buflen);

/* ------------------------------------------------------------------ */
/*  Comparison                                                        */
/* ------------------------------------------------------------------ */

/* Compare absolute values. Returns -1, 0, or 1. */
int mbedcrypto_bn_cmp_magnitude(const struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *Y);

/* Compare signed values. Returns -1, 0, or 1. */
int mbedcrypto_bn_cmp(const struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *Y);

/* Compare with a signed integer. Returns -1, 0, or 1. */
int mbedcrypto_bn_cmp_word(const struct mbedcrypto_bignum *X, int z);

/* ------------------------------------------------------------------ */
/*  Arithmetic                                                        */
/* ------------------------------------------------------------------ */

/* X = A + B */
int mbedcrypto_bn_add(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B);

/* X = A - B */
int mbedcrypto_bn_sub(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B);

/* X = A + b (signed integer) */
int mbedcrypto_bn_add_word(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A, int b);

/* X = A * B */
int mbedcrypto_bn_mul(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B);

/* X = A * B, using T as pre-allocated product temp (avoids alloc). */
int mbedcrypto_bn_mul_karatsuba(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B,
		struct mbedcrypto_bignum *T);

/* X = A * b (unsigned word-sized integer) */
int mbedcrypto_bn_mul_word(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		bn_word_t b);

/*
 * Q = A / B, R = A mod B.
 * Either Q or R may be NULL.
 */
int mbedcrypto_bn_div(struct mbedcrypto_bignum *Q,
		struct mbedcrypto_bignum *R,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B);

/* R = A mod B (always non-negative: 0 <= R < |B|) */
int mbedcrypto_bn_mod(struct mbedcrypto_bignum *R,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B);

/* ------------------------------------------------------------------ */
/*  Modular operations                                                */
/* ------------------------------------------------------------------ */

/*
 * X = A^E mod N.
 * RR may be a pre-computed R^2 mod N for Montgomery, or NULL.
 */
int mbedcrypto_bn_modpow(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *E,
		const struct mbedcrypto_bignum *N,
		struct mbedcrypto_bignum *RR);

/* X = A^(-1) mod N */
int mbedcrypto_bn_modinv(struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *N);

/* ------------------------------------------------------------------ */
/*  Random and prime generation                                       */
/* ------------------------------------------------------------------ */

/* Fill X with 'size' random bytes. */
int mbedcrypto_bn_random(struct mbedcrypto_bignum *X, size_t size,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/* Primality test rounds. */
#define MBEDCRYPTO_BN_PRIME_CHECK_ROUNDS  40

/*
 * Miller-Rabin primality test.
 * Returns 0 if probably prime, -EINVAL if composite.
 * 'rounds' is the number of Miller-Rabin witnesses.
 */
int mbedcrypto_bn_test_prime(const struct mbedcrypto_bignum *X, int rounds,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * Generate a prime number.
 * flags: bit 0 = DH-safe ((X-1)/2 is also prime).
 * Returns 0 on success.
 */
#define MBEDCRYPTO_BN_GEN_PRIME_FLAG_DH  0x01

int mbedcrypto_bn_gen_prime(struct mbedcrypto_bignum *X, size_t nbits,
		int flags, mbedcrypto_rng_fn f_rng, void *p_rng);

/* ------------------------------------------------------------------ */
/*  GCD                                                               */
/* ------------------------------------------------------------------ */

/*
 * Extended GCD: u*x + v*y = gcd.
 * Either u or v may be NULL if not needed.
 */
int mbedcrypto_bn_egcd(struct mbedcrypto_bignum *gcd,
		struct mbedcrypto_bignum *u, struct mbedcrypto_bignum *v,
		const struct mbedcrypto_bignum *x,
		const struct mbedcrypto_bignum *y);

/*
 * Greatest common divisor: G = gcd(A, B).
 * Convenience wrapper around mbedcrypto_bn_egcd.
 */
int mbedcrypto_bn_gcd(struct mbedcrypto_bignum *G,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B);

#endif /* _MBEDCRYPTO_BIGNUM_H */
