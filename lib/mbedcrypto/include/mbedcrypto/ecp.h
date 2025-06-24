/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Elliptic Curve Point arithmetic and curve parameters
 *
 * Short-Weierstrass curves: y^2 = x^3 + ax + b  (mod P)
 * Montgomery curves:        By^2 = x^3 + Ax^2 + x (mod P)
 */

#ifndef _MBEDCRYPTO_ECP_H
#define _MBEDCRYPTO_ECP_H

#include <mbedcrypto/bignum.h>

/*
 * Curve identifiers.
 */
#define MBEDCRYPTO_ECP_DP_NONE       0
#define MBEDCRYPTO_ECP_DP_SECP192R1  1
#define MBEDCRYPTO_ECP_DP_SECP256R1  2
#define MBEDCRYPTO_ECP_DP_SECP384R1  3
#define MBEDCRYPTO_ECP_DP_SECP521R1  4
#define MBEDCRYPTO_ECP_DP_BP256R1    5
#define MBEDCRYPTO_ECP_DP_BP384R1    6
#define MBEDCRYPTO_ECP_DP_BP512R1    7
#define MBEDCRYPTO_ECP_DP_CURVE25519 8
#define MBEDCRYPTO_ECP_DP_SM2        9

/*
 * Curve type.
 */
#define MBEDCRYPTO_ECP_TYPE_SHORT_WEIERSTRASS 0
#define MBEDCRYPTO_ECP_TYPE_MONTGOMERY       1

/*
 * Point in affine or Jacobian coordinates (X, Y, Z).
 * Affine: Z = 1, point = (X, Y).
 * At infinity: Z = 0.
 */
struct mbedcrypto_ecp_point {
	struct mbedcrypto_bignum X;
	struct mbedcrypto_bignum Y;
	struct mbedcrypto_bignum Z;
};

/*
 * Curve group parameters.
 */
#define ECP_SCRATCH_CNT 10  /* 9 func temps + 1 product temp */

struct mbedcrypto_ecp_group {
	uint8_t id;
	uint8_t type;
	struct mbedcrypto_bignum P;       /* prime modulus */
	struct mbedcrypto_bignum A;       /* a  (or A for Montgomery) */
	struct mbedcrypto_bignum B;       /* b  (or B for Montgomery) */
	struct mbedcrypto_ecp_point G; /* base point / generator */
	struct mbedcrypto_bignum N;       /* order of G */
	size_t pbits;                  /* bit-length of P */
	size_t nbits;                  /* bit-length of N */
	int (*fast_mod)(struct mbedcrypto_bignum *); /* NIST fast reduction or NULL */
	struct mbedcrypto_ecp_point *gen_table; /* precomputed comb table for G */
	size_t gen_tlen;                        /* number of entries in gen_table */
	struct mbedcrypto_bignum scratch[ECP_SCRATCH_CNT]; /* reusable temps */
};

/*
 * ECC keypair: private scalar d and public point Q.
 */
struct mbedcrypto_ecp_keypair {
	struct mbedcrypto_ecp_group grp;
	struct mbedcrypto_bignum d;      /* private scalar */
	struct mbedcrypto_ecp_point Q; /* public point */
};

/* ---------------------------------------------------------------- */
/* Point lifecycle                                                  */
/* ---------------------------------------------------------------- */

void mbedcrypto_ecp_point_init(struct mbedcrypto_ecp_point *pt);
void mbedcrypto_ecp_point_cleanup(struct mbedcrypto_ecp_point *pt);

/* ---------------------------------------------------------------- */
/* Group lifecycle                                                  */
/* ---------------------------------------------------------------- */

void mbedcrypto_ecp_group_init(struct mbedcrypto_ecp_group *grp);
void mbedcrypto_ecp_group_cleanup(struct mbedcrypto_ecp_group *grp);

/* Load a named curve's parameters. */
int mbedcrypto_ecp_load_group(struct mbedcrypto_ecp_group *grp, int id);

/* ---------------------------------------------------------------- */
/* Keypair lifecycle                                                */
/* ---------------------------------------------------------------- */

void mbedcrypto_ecp_keypair_init(struct mbedcrypto_ecp_keypair *key);
void mbedcrypto_ecp_keypair_cleanup(struct mbedcrypto_ecp_keypair *key);

/* ---------------------------------------------------------------- */
/* Point operations                                                 */
/* ---------------------------------------------------------------- */

/* Check if point is at infinity (Z == 0). */
int mbedcrypto_ecp_is_infinity(const struct mbedcrypto_ecp_point *pt);

/*
 * Scalar multiplication: R = m * P.
 * For short-Weierstrass curves.
 */
int mbedcrypto_ecp_scalar_mul(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *R,
		const struct mbedcrypto_bignum *m,
		const struct mbedcrypto_ecp_point *P,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * Dual scalar multiplication: R = m * P + n * Q.
 * Used in ECDSA verification (Shamir's trick).
 */
int mbedcrypto_ecp_dual_scalar_mul(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *R,
		const struct mbedcrypto_bignum *m,
		const struct mbedcrypto_ecp_point *P,
		const struct mbedcrypto_bignum *n,
		const struct mbedcrypto_ecp_point *Q);

/*
 * Check that a point lies on the curve.
 * Returns 0 if valid, -EINVAL if not.
 */
int mbedcrypto_ecp_validate_point(struct mbedcrypto_ecp_group *grp,
		const struct mbedcrypto_ecp_point *pt);

/* ---------------------------------------------------------------- */
/* Key generation                                                   */
/* ---------------------------------------------------------------- */

/*
 * Generate a keypair on the given curve.
 *   key->grp must be loaded first, or pass group_id.
 */
int mbedcrypto_ecp_keygen(int grp_id,
		struct mbedcrypto_ecp_keypair *key,
		mbedcrypto_rng_fn f_rng, void *p_rng);

#endif /* _MBEDCRYPTO_ECP_H */
