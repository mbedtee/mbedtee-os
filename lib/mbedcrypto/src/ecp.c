// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Elliptic Curve Point arithmetic and curve parameters
 *
 * Short-Weierstrass:  y^2 = x^3 + ax + b (mod P)
 *   Jacobian coordinates (X:Y:Z) with  x = X/Z^2, y = Y/Z^3.
 *
 * Montgomery (Curve25519):  By^2 = x^3 + Ax^2 + x (mod P)
 *   Montgomery ladder operating on X-only coordinates.
 */

#include <string.h>
#include <stdlib.h>

#include <mbedcrypto/ecp.h>
#include <mbedcrypto/types.h>

#define ECP_SCRATCH_PROD 9  /* index of the product temp */

/* ---------------------------------------------------------------- */
/* NIST P-256 fast modular reduction (FIPS 186-4, D.2.3)           */
/* ---------------------------------------------------------------- */

static int mod_p256(struct mbedcrypto_bignum *N)
{
	int ret = 0;
	size_t nbits = mbedcrypto_bn_bit_count(N);

	if (nbits > 256) {
		uint32_t A[16];
		int64_t S[8], carry;
		int i = 0;

		if ((ret = mbedcrypto_bn_expand(N, 8)) != 0)
			return ret;

		/* Extract 32-bit words directly from 64-bit words */
#if BN_WORD_BITS == 64
		for (i = 0; i < 8 && i < N->used; i++) {
			A[2 * i]     = (uint32_t)N->data[i];
			A[2 * i + 1] = N->data[i] >> 32;
		}
		for (; i < 8; i++) {
			A[2 * i] = 0;
			A[2 * i + 1] = 0;
		}
#else
		for (i = 0; i < 16 && i < N->used; i++)
			A[i] = N->data[i];
		for (; i < 16; i++)
			A[i] = 0;
#endif

		/* FIPS 186-4, D.2.3 - NIST P-256 fast reduction */
		S[0] = (int64_t)A[0] + A[8] + A[9]
		     - A[11] - A[12] - A[13] - A[14];
		S[1] = (int64_t)A[1] + A[9] + A[10]
		     - A[12] - A[13] - A[14] - A[15];
		S[2] = (int64_t)A[2] + A[10] + A[11]
		     - A[13] - A[14] - A[15];
		S[3] = (int64_t)A[3] + 2*(int64_t)A[11] + 2*(int64_t)A[12]
		     + A[13] - A[15] - A[8] - A[9];
		S[4] = (int64_t)A[4] + 2*(int64_t)A[12] + 2*(int64_t)A[13]
		     + A[14] - A[9] - A[10];
		S[5] = (int64_t)A[5] + 2*(int64_t)A[13] + 2*(int64_t)A[14]
		     + A[15] - A[10] - A[11];
		S[6] = (int64_t)A[6] + A[13] + 3*(int64_t)A[14]
		     + 2*(int64_t)A[15] - A[8] - A[9];
		S[7] = (int64_t)A[7] + A[8] + 3*(int64_t)A[15]
		     - A[10] - A[11] - A[12] - A[13];

		carry = 0;
		for (i = 0; i < 8; i++) {
			int64_t v = S[i] + carry;
			S[i] = v & 0xFFFFFFFF;
			carry = (v - S[i]) >> 32;
		}

		while (carry != 0) {
			int64_t c = carry;
			carry = 0;
			S[0] += c;  S[3] -= c;
			S[6] -= c;  S[7] += c;
			for (i = 0; i < 8; i++) {
				int64_t v = S[i] + carry;
				S[i] = v & 0xFFFFFFFF;
				carry = (v - S[i]) >> 32;
			}
		}

		/* Write 32-bit words back to 64-bit words */
#if BN_WORD_BITS == 64
		N->data[0] = (uint64_t)(uint32_t)S[0] |
			     ((uint64_t)(uint32_t)S[1] << 32);
		N->data[1] = (uint64_t)(uint32_t)S[2] |
			     ((uint64_t)(uint32_t)S[3] << 32);
		N->data[2] = (uint64_t)(uint32_t)S[4] |
			     ((uint64_t)(uint32_t)S[5] << 32);
		N->data[3] = (uint64_t)(uint32_t)S[6] |
			     ((uint64_t)(uint32_t)S[7] << 32);
		for (i = 4; i < N->used; i++)
			N->data[i] = 0;
#else
		for (i = 0; i < 8; i++)
			N->data[i] = (uint32_t)S[i];
		for (i = 8; i < N->used; i++)
			N->data[i] = 0;
#endif
	}

	{
		bn_word_t p_data[] = {
#if BN_WORD_BITS == 64
			0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
			0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
#else
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
			0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
#endif
		};
		struct mbedcrypto_bignum PP;
		PP.neg = 0;
		PP.used = sizeof(p_data) / sizeof(p_data[0]);
		PP.capacity = 0;
		PP.data = p_data;
		while (mbedcrypto_bn_cmp(N, &PP) >= 0) {
			ret = mbedcrypto_bn_sub(N, N, &PP);
			if (ret != 0)
				return ret;
		}
	}
	return 0;
}


/* ---------------------------------------------------------------- */
/* NIST P-384 fast modular reduction (FIPS 186-4, D.2.4)           */
/* p = 2^384 - 2^128 - 2^96 + 2^32 - 1                            */
/* ---------------------------------------------------------------- */

static int mod_p384(struct mbedcrypto_bignum *N)
{
	int ret = 0;
	size_t nbits = mbedcrypto_bn_bit_count(N);

	if (nbits > 384) {
		uint32_t c[24];
		int64_t S[12], carry;
		int i = 0;

		if ((ret = mbedcrypto_bn_expand(N, 12)) != 0)
			return ret;

		/* Extract 32-bit words directly from words */
#if BN_WORD_BITS == 64
		for (i = 0; i < 12 && i < N->used; i++) {
			c[2 * i]     = (uint32_t)N->data[i];
			c[2 * i + 1] = N->data[i] >> 32;
		}
		for (; i < 12; i++) {
			c[2 * i] = 0;
			c[2 * i + 1] = 0;
		}
#else
		for (i = 0; i < 24 && i < N->used; i++)
			c[i] = N->data[i];
		for (; i < 24; i++)
			c[i] = 0;
#endif

		S[0]  = (int64_t)c[0] + c[12] + c[20] + c[21]
			- c[23];
		S[1]  = (int64_t)c[1] + c[13] + c[22] + c[23]
			- c[12] - c[20];
		S[2]  = (int64_t)c[2] + c[14] + c[23]
			- c[13] - c[21];
		S[3]  = (int64_t)c[3] + c[12] + c[15] + c[20] + c[21]
			- c[14] - c[22] - c[23];
		S[4]  = (int64_t)c[4] + c[12] + c[13] + c[16] + c[20]
			+ 2*(int64_t)c[21] + c[22]
			- c[15] - 2*(int64_t)c[23];
		S[5]  = (int64_t)c[5] + c[13] + c[14] + c[17] + c[21]
			+ 2*(int64_t)c[22] + c[23]
			- c[16];
		S[6]  = (int64_t)c[6] + c[14] + c[15] + c[18] + c[22]
			+ 2*(int64_t)c[23]
			- c[17];
		S[7]  = (int64_t)c[7] + c[15] + c[16] + c[19] + c[23]
			- c[18];
		S[8]  = (int64_t)c[8] + c[16] + c[17] + c[20]
			- c[19];
		S[9]  = (int64_t)c[9] + c[17] + c[18] + c[21]
			- c[20];
		S[10] = (int64_t)c[10] + c[18] + c[19] + c[22]
			- c[21];
		S[11] = (int64_t)c[11] + c[19] + c[20] + c[23]
			- c[22];

		carry = 0;
		for (i = 0; i < 12; i++) {
			int64_t v = S[i] + carry;
			S[i] = v & 0xFFFFFFFF;
			carry = (v - S[i]) >> 32;
		}

		while (carry != 0) {
			int64_t cr = carry;
			carry = 0;
			S[0]  += cr;
			S[1]  -= cr;
			S[3]  += cr;
			S[4]  += cr;
			for (i = 0; i < 12; i++) {
				int64_t v = S[i] + carry;
				S[i] = v & 0xFFFFFFFF;
				carry = (v - S[i]) >> 32;
			}
		}

		/* Write 32-bit words back to words */
#if BN_WORD_BITS == 64
		N->data[0] = (uint64_t)(uint32_t)S[0] |
			     ((uint64_t)(uint32_t)S[1] << 32);
		N->data[1] = (uint64_t)(uint32_t)S[2] |
			     ((uint64_t)(uint32_t)S[3] << 32);
		N->data[2] = (uint64_t)(uint32_t)S[4] |
			     ((uint64_t)(uint32_t)S[5] << 32);
		N->data[3] = (uint64_t)(uint32_t)S[6] |
			     ((uint64_t)(uint32_t)S[7] << 32);
		N->data[4] = (uint64_t)(uint32_t)S[8] |
			     ((uint64_t)(uint32_t)S[9] << 32);
		N->data[5] = (uint64_t)(uint32_t)S[10] |
			     ((uint64_t)(uint32_t)S[11] << 32);
		for (i = 6; i < N->used; i++)
			N->data[i] = 0;
#else
		for (i = 0; i < 12; i++)
			N->data[i] = (uint32_t)S[i];
		for (i = 12; i < N->used; i++)
			N->data[i] = 0;
#endif
	}

	{
		bn_word_t p_data[] = {
#if BN_WORD_BITS == 64
			0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL,
			0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL,
			0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
#else
			0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF,
			0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
#endif
		};
		struct mbedcrypto_bignum PP;
		PP.neg = 0;
		PP.used = sizeof(p_data) / sizeof(p_data[0]);
		PP.capacity = 0;
		PP.data = p_data;
		while (mbedcrypto_bn_cmp(N, &PP) >= 0) {
			ret = mbedcrypto_bn_sub(N, N, &PP);
			if (ret != 0)
				return ret;
		}
	}
	return 0;
}


/* ---------------------------------------------------------------- */
/* NIST P-521 fast modular reduction (FIPS 186-4, D.2.5)           */
/* p = 2^521 - 1 (Mersenne prime)                                  */
/* ---------------------------------------------------------------- */

static int mod_p521(struct mbedcrypto_bignum *N)
{
	int ret = 0;
	struct mbedcrypto_bignum M;
	size_t nbits = mbedcrypto_bn_bit_count(N);
	size_t word_idx = 0, bit_ofs = 0;

	if (nbits <= 521)
		return 0;

	/*
	 * For the Mersenne prime p = 2^521 - 1:
	 * N mod p = (N >> 521) + (N & p)  (mod p)
	 *
	 * This works because 2^521 = 1 (mod p).
	 */
	mbedcrypto_bn_init(&M);

	/* M = upper part = N >> 521 */
	ret = mbedcrypto_bn_copy(&M, N);
	if (ret != 0)
		goto out;
	ret = mbedcrypto_bn_rshift(&M, 521);
	if (ret != 0)
		goto out;

	/* Mask N to lower 521 bits */
	word_idx = 521 / BN_WORD_BITS;
	bit_ofs = 521 % BN_WORD_BITS;
	if (word_idx < N->used) {
		size_t k = 0;

		N->data[word_idx] &= ((bn_word_t)1 << bit_ofs) - 1;
		for (k = word_idx + 1; k < N->used; k++)
			N->data[k] = 0;
	}

	/* N = lower + upper */
	ret = mbedcrypto_bn_add(N, N, &M);
	if (ret != 0)
		goto out;

	/* Final reduction: if N >= p, subtract p (at most once) */
	{
		bn_word_t p_data[] = {
#if BN_WORD_BITS == 64
			0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
			0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
			0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
			0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
			0x1FFULL
#else
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
			0x1FF
#endif
		};
		struct mbedcrypto_bignum PP;
		PP.neg = 0;
		PP.used = sizeof(p_data) / sizeof(p_data[0]);
		PP.capacity = 0;
		PP.data = p_data;
		while (mbedcrypto_bn_cmp(N, &PP) >= 0) {
			ret = mbedcrypto_bn_sub(N, N, &PP);
			if (ret != 0)
				goto out;
		}
	}

out:
	mbedcrypto_bn_cleanup(&M);
	return ret;
}


/* ---------------------------------------------------------------- */
/* NIST P-192 (secp192r1)                                           */
/* ---------------------------------------------------------------- */

static int ecp_load_secp192r1(struct mbedcrypto_ecp_group *grp)
{
	int ret = 0;

	ret  = mbedcrypto_bn_from_hex(&grp->P,
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
	ret |= mbedcrypto_bn_set_word(&grp->A, -3);
	ret |= mbedcrypto_bn_from_hex(&grp->B,
		"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
	ret |= mbedcrypto_bn_from_hex(&grp->G.X,
		"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012");
	ret |= mbedcrypto_bn_from_hex(&grp->G.Y,
		"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811");
	ret |= mbedcrypto_bn_set_word(&grp->G.Z, 1);
	ret |= mbedcrypto_bn_from_hex(&grp->N,
		"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
	if (ret != 0)
		return ret;

	grp->pbits = 192;
	grp->nbits = 192;
	return 0;
}

/* ---------------------------------------------------------------- */
/* NIST P-256 (secp256r1)                                           */
/* ---------------------------------------------------------------- */

static int ecp_load_secp256r1(struct mbedcrypto_ecp_group *grp)
{
	int ret = 0;

	ret  = mbedcrypto_bn_from_hex(&grp->P,
		"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
	ret |= mbedcrypto_bn_set_word(&grp->A, -3);
	ret |= mbedcrypto_bn_from_hex(&grp->B,
		"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
	ret |= mbedcrypto_bn_from_hex(&grp->G.X,
		"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
	ret |= mbedcrypto_bn_from_hex(&grp->G.Y,
		"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
	ret |= mbedcrypto_bn_set_word(&grp->G.Z, 1);
	ret |= mbedcrypto_bn_from_hex(&grp->N,
		"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
	if (ret != 0)
		return ret;

	grp->pbits = 256;
	grp->nbits = 256;
	grp->fast_mod = mod_p256;
	return 0;
}

/* ---------------------------------------------------------------- */
/* NIST P-384 (secp384r1)                                           */
/* ---------------------------------------------------------------- */

static int ecp_load_secp384r1(struct mbedcrypto_ecp_group *grp)
{
	int ret = 0;

	ret  = mbedcrypto_bn_from_hex(&grp->P,
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
		"FFFFFFFF0000000000000000FFFFFFFF");
	ret |= mbedcrypto_bn_set_word(&grp->A, -3);
	ret |= mbedcrypto_bn_from_hex(&grp->B,
		"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
		"C656398D8A2ED19D2A85C8EDD3EC2AEF");
	ret |= mbedcrypto_bn_from_hex(&grp->G.X,
		"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
		"5502F25DBF55296C3A545E3872760AB7");
	ret |= mbedcrypto_bn_from_hex(&grp->G.Y,
		"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
		"0A60B1CE1D7E819D7A431D7C90EA0E5F");
	ret |= mbedcrypto_bn_set_word(&grp->G.Z, 1);
	ret |= mbedcrypto_bn_from_hex(&grp->N,
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
		"581A0DB248B0A77AECEC196ACCC52973");
	if (ret != 0)
		return ret;

	grp->pbits = 384;
	grp->nbits = 384;
	grp->fast_mod = mod_p384;
	return 0;
}

/* ---------------------------------------------------------------- */
/* NIST P-521 (secp521r1)                                           */
/* ---------------------------------------------------------------- */

static int ecp_load_secp521r1(struct mbedcrypto_ecp_group *grp)
{
	int ret = 0;

	ret  = mbedcrypto_bn_from_hex(&grp->P,
		"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFF");
	ret |= mbedcrypto_bn_set_word(&grp->A, -3);
	ret |= mbedcrypto_bn_from_hex(&grp->B,
		"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
		"09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
		"3F00");
	ret |= mbedcrypto_bn_from_hex(&grp->G.X,
		"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D"
		"3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5"
		"BD66");
	ret |= mbedcrypto_bn_from_hex(&grp->G.Y,
		"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
		"662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16"
		"650");
	ret |= mbedcrypto_bn_set_word(&grp->G.Z, 1);
	ret |= mbedcrypto_bn_from_hex(&grp->N,
		"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E9138"
		"6409");
	if (ret != 0)
		return ret;

	grp->pbits = 521;
	grp->nbits = 521;
	grp->fast_mod = mod_p521;
	return 0;
}

/* ---------------------------------------------------------------- */
/* Brainpool P-256r1                                                */
/* ---------------------------------------------------------------- */

static int ecp_load_bp256r1(struct mbedcrypto_ecp_group *grp)
{
	int ret = 0;

	ret  = mbedcrypto_bn_from_hex(&grp->P,
		"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377");
	ret |= mbedcrypto_bn_from_hex(&grp->A,
		"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9");
	ret |= mbedcrypto_bn_from_hex(&grp->B,
		"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6");
	ret |= mbedcrypto_bn_from_hex(&grp->G.X,
		"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262");
	ret |= mbedcrypto_bn_from_hex(&grp->G.Y,
		"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997");
	ret |= mbedcrypto_bn_set_word(&grp->G.Z, 1);
	ret |= mbedcrypto_bn_from_hex(&grp->N,
		"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7");
	if (ret != 0)
		return ret;

	grp->pbits = 256;
	grp->nbits = 256;
	return 0;
}

/* ---------------------------------------------------------------- */
/* Brainpool P-384r1                                                */
/* ---------------------------------------------------------------- */

static int ecp_load_bp384r1(struct mbedcrypto_ecp_group *grp)
{
	int ret = 0;

	ret  = mbedcrypto_bn_from_hex(&grp->P,
		"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123"
		"ACD3A729901D1A71874700133107EC53");
	ret |= mbedcrypto_bn_from_hex(&grp->A,
		"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F"
		"8AA5814A503AD4EB04A8C7DD22CE2826");
	ret |= mbedcrypto_bn_from_hex(&grp->B,
		"04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D5"
		"7CB4390295DBC9943AB78696FA504C11");
	ret |= mbedcrypto_bn_from_hex(&grp->G.X,
		"1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8"
		"E826E03436D646AAEF87B2E247D4AF1E");
	ret |= mbedcrypto_bn_from_hex(&grp->G.Y,
		"8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF9912928"
		"0E4646217791811142820341263C5315");
	ret |= mbedcrypto_bn_set_word(&grp->G.Z, 1);
	ret |= mbedcrypto_bn_from_hex(&grp->N,
		"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7"
		"CF3AB6AF6B7FC3103B883202E9046565");
	if (ret != 0)
		return ret;

	grp->pbits = 384;
	grp->nbits = 384;
	return 0;
}

/* ---------------------------------------------------------------- */
/* Brainpool P-512r1                                                */
/* ---------------------------------------------------------------- */

static int ecp_load_bp512r1(struct mbedcrypto_ecp_group *grp)
{
	int ret = 0;

	ret  = mbedcrypto_bn_from_hex(&grp->P,
		"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308"
		"717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3");
	ret |= mbedcrypto_bn_from_hex(&grp->A,
		"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC"
		"2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA");
	ret |= mbedcrypto_bn_from_hex(&grp->B,
		"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A7"
		"2BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723");
	ret |= mbedcrypto_bn_from_hex(&grp->G.X,
		"81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098"
		"EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822");
	ret |= mbedcrypto_bn_from_hex(&grp->G.Y,
		"7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111"
		"B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892");
	ret |= mbedcrypto_bn_set_word(&grp->G.Z, 1);
	ret |= mbedcrypto_bn_from_hex(&grp->N,
		"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308"
		"70553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA9006"
		"9");
	if (ret != 0)
		return ret;

	grp->pbits = 512;
	grp->nbits = 512;
	return 0;
}

/* ---------------------------------------------------------------- */
/* Curve25519                                                       */
/* ---------------------------------------------------------------- */

static int ecp_load_curve25519(struct mbedcrypto_ecp_group *grp)
{
	int ret = 0;

	/* P = 2^255 - 19 */
	ret  = mbedcrypto_bn_from_hex(&grp->P,
		"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED");
	ret |= mbedcrypto_bn_set_word(&grp->A, 486662);
	ret |= mbedcrypto_bn_set_word(&grp->B, 1);
	/* Base point (u = 9) */
	ret |= mbedcrypto_bn_set_word(&grp->G.X, 9);
	ret |= mbedcrypto_bn_set_word(&grp->G.Y, 0);
	ret |= mbedcrypto_bn_set_word(&grp->G.Z, 1);
	ret |= mbedcrypto_bn_from_hex(&grp->N,
		"1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED");
	if (ret != 0)
		return ret;

	grp->pbits = 255;
	grp->nbits = 253;
	return 0;
}

static int ecp_load_sm2(struct mbedcrypto_ecp_group *grp)
{
	int ret = 0;

	/* SM2 curve parameters (GB/T 32918.5-2017) */
	ret  = mbedcrypto_bn_from_hex(&grp->P,
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
	ret |= mbedcrypto_bn_set_word(&grp->A, -3);
	ret |= mbedcrypto_bn_from_hex(&grp->B,
		"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
	ret |= mbedcrypto_bn_from_hex(&grp->G.X,
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
	ret |= mbedcrypto_bn_from_hex(&grp->G.Y,
		"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
	ret |= mbedcrypto_bn_set_word(&grp->G.Z, 1);
	ret |= mbedcrypto_bn_from_hex(&grp->N,
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
	if (ret != 0)
		return ret;

	grp->pbits = 256;
	grp->nbits = 256;
	return 0;
}

/* ---------------------------------------------------------------- */
/* Point lifecycle                                                  */
/* ---------------------------------------------------------------- */

void mbedcrypto_ecp_point_init(struct mbedcrypto_ecp_point *pt)
{
	mbedcrypto_bn_init(&pt->X);
	mbedcrypto_bn_init(&pt->Y);
	mbedcrypto_bn_init(&pt->Z);
}

void mbedcrypto_ecp_point_cleanup(struct mbedcrypto_ecp_point *pt)
{
	mbedcrypto_bn_cleanup(&pt->X);
	mbedcrypto_bn_cleanup(&pt->Y);
	mbedcrypto_bn_cleanup(&pt->Z);
}

static int ecp_point_copy(struct mbedcrypto_ecp_point *R,
		const struct mbedcrypto_ecp_point *P)
{
	int ret = 0;

	ret  = mbedcrypto_bn_copy(&R->X, &P->X);
	ret |= mbedcrypto_bn_copy(&R->Y, &P->Y);
	ret |= mbedcrypto_bn_copy(&R->Z, &P->Z);
	return ret;
}

int mbedcrypto_ecp_is_infinity(const struct mbedcrypto_ecp_point *pt)
{
	return (mbedcrypto_bn_cmp_word(&pt->Z, 0) == 0);
}

static int ecp_set_zero(struct mbedcrypto_ecp_point *pt)
{
	int ret = 0;

	ret  = mbedcrypto_bn_set_word(&pt->X, 1);
	ret |= mbedcrypto_bn_set_word(&pt->Y, 1);
	ret |= mbedcrypto_bn_set_word(&pt->Z, 0);
	return ret;
}

/* ---------------------------------------------------------------- */
/* Group lifecycle                                                  */
/* ---------------------------------------------------------------- */

void mbedcrypto_ecp_group_init(struct mbedcrypto_ecp_group *grp)
{
	int i = 0;

	memset(grp, 0, sizeof(*grp));
	mbedcrypto_bn_init(&grp->P);
	mbedcrypto_bn_init(&grp->A);
	mbedcrypto_bn_init(&grp->B);
	mbedcrypto_ecp_point_init(&grp->G);
	mbedcrypto_bn_init(&grp->N);
	for (i = 0; i < ECP_SCRATCH_CNT; i++)
		mbedcrypto_bn_init(&grp->scratch[i]);
}

void mbedcrypto_ecp_group_cleanup(struct mbedcrypto_ecp_group *grp)
{
	size_t i = 0;

	if (grp->gen_table) {
		for (i = 0; i < grp->gen_tlen; i++)
			mbedcrypto_ecp_point_cleanup(&grp->gen_table[i]);
		free(grp->gen_table);
	}
	mbedcrypto_bn_cleanup(&grp->P);
	mbedcrypto_bn_cleanup(&grp->A);
	mbedcrypto_bn_cleanup(&grp->B);
	mbedcrypto_ecp_point_cleanup(&grp->G);
	mbedcrypto_bn_cleanup(&grp->N);
	for (i = 0; i < ECP_SCRATCH_CNT; i++)
		mbedcrypto_bn_cleanup(&grp->scratch[i]);
	memset(grp, 0, sizeof(*grp));
}

int mbedcrypto_ecp_load_group(struct mbedcrypto_ecp_group *grp,
		int id)
{
	int ret = 0;

	mbedcrypto_ecp_group_cleanup(grp);
	mbedcrypto_ecp_group_init(grp);
	grp->id = id;

	switch (id) {
	case MBEDCRYPTO_ECP_DP_SECP192R1:
		grp->type = MBEDCRYPTO_ECP_TYPE_SHORT_WEIERSTRASS;
		ret = ecp_load_secp192r1(grp);
		break;
	case MBEDCRYPTO_ECP_DP_SECP256R1:
		grp->type = MBEDCRYPTO_ECP_TYPE_SHORT_WEIERSTRASS;
		ret = ecp_load_secp256r1(grp);
		break;
	case MBEDCRYPTO_ECP_DP_SECP384R1:
		grp->type = MBEDCRYPTO_ECP_TYPE_SHORT_WEIERSTRASS;
		ret = ecp_load_secp384r1(grp);
		break;
	case MBEDCRYPTO_ECP_DP_SECP521R1:
		grp->type = MBEDCRYPTO_ECP_TYPE_SHORT_WEIERSTRASS;
		ret = ecp_load_secp521r1(grp);
		break;
	case MBEDCRYPTO_ECP_DP_BP256R1:
		grp->type = MBEDCRYPTO_ECP_TYPE_SHORT_WEIERSTRASS;
		ret = ecp_load_bp256r1(grp);
		break;
	case MBEDCRYPTO_ECP_DP_BP384R1:
		grp->type = MBEDCRYPTO_ECP_TYPE_SHORT_WEIERSTRASS;
		ret = ecp_load_bp384r1(grp);
		break;
	case MBEDCRYPTO_ECP_DP_BP512R1:
		grp->type = MBEDCRYPTO_ECP_TYPE_SHORT_WEIERSTRASS;
		ret = ecp_load_bp512r1(grp);
		break;
	case MBEDCRYPTO_ECP_DP_CURVE25519:
		grp->type = MBEDCRYPTO_ECP_TYPE_MONTGOMERY;
		ret = ecp_load_curve25519(grp);
		break;
	case MBEDCRYPTO_ECP_DP_SM2:
		grp->type = MBEDCRYPTO_ECP_TYPE_SHORT_WEIERSTRASS;
		ret = ecp_load_sm2(grp);
		break;
	default:
		return -EINVAL;
	}

	if (ret != 0)
		mbedcrypto_ecp_group_cleanup(grp);
	return ret;
}

/* ---------------------------------------------------------------- */
/* Keypair lifecycle                                                */
/* ---------------------------------------------------------------- */

void mbedcrypto_ecp_keypair_init(struct mbedcrypto_ecp_keypair *key)
{
	mbedcrypto_ecp_group_init(&key->grp);
	mbedcrypto_bn_init(&key->d);
	mbedcrypto_ecp_point_init(&key->Q);
}

void mbedcrypto_ecp_keypair_cleanup(struct mbedcrypto_ecp_keypair *key)
{
	mbedcrypto_ecp_group_cleanup(&key->grp);
	mbedcrypto_bn_cleanup(&key->d);
	mbedcrypto_ecp_point_cleanup(&key->Q);
}

/* ---------------------------------------------------------------- */
/* Modular reduction with NIST fast path                            */
/* ---------------------------------------------------------------- */

static int ecp_fast_mod(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_bignum *R)
{
	int ret = 0, neg = 0;

	if (grp->fast_mod) {
		/*
		 * Fast reduction functions (mod_p384, mod_p521, etc.)
		 * operate on the absolute value and call bn_read_binary
		 * which resets the sign to +1. We must strip the sign
		 * before calling, then apply: -|R| mod P = P - (|R| mod P).
		 */
		neg = (R->neg);
		if (neg)
			R->neg = 0;

		ret = grp->fast_mod(R);
		if (ret != 0)
			return ret;

		if (neg && mbedcrypto_bn_bit_count(R) != 0)
			return mbedcrypto_bn_sub(R, &grp->P, R);
	} else {
		ret = mbedcrypto_bn_mod(R, R, &grp->P);
		if (ret != 0)
			return ret;
	}

	/* Handle any remaining negative values (e.g., from subtraction) */
	while (R->neg) {
		ret = mbedcrypto_bn_add(R, R, &grp->P);
		if (ret != 0)
			return ret;
	}
	return 0;
}


/* Ensure all scratch bignums are pre-grown for the curve. */
static int ecp_scratch_init(struct mbedcrypto_ecp_group *grp)
{
	int i = 0, ret = 0;
	size_t cap = 2 * grp->P.used + 2;

	if (grp->scratch[0].capacity >= cap)
		return 0;

	for (i = 0; i < ECP_SCRATCH_CNT; i++) {
		if ((ret = mbedcrypto_bn_expand(&grp->scratch[i], cap)) != 0)
			return ret;
	}
	return 0;
}


/*
 * Field multiply-and-reduce: X = A * B mod P.
 * Uses grp->scratch[ECP_SCRATCH_PROD] as the product temp.
 */
static int ecp_mul_mod(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		const struct mbedcrypto_bignum *B)
{
	int ret = 0;

	if ((ret = mbedcrypto_bn_mul_karatsuba(X, A, B,
					 &grp->scratch[ECP_SCRATCH_PROD])) != 0)
		return ret;

	return ecp_fast_mod(grp, X);
}


/*
 * Field multiply-by-int-and-reduce: X = A * b mod P.
 */
static int ecp_mul_int_mod(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_bignum *X,
		const struct mbedcrypto_bignum *A,
		bn_word_t b)
{
	struct mbedcrypto_bignum B;

	B.neg = 0;
	B.used = 1;
	B.capacity = 0;
	B.data = &b;

	return ecp_mul_mod(grp, X, A, &B);
}


/* ---------------------------------------------------------------- */
/* Short-Weierstrass: Jacobian point doubling                       */
/*                                                                  */
/* 2P with a = -3 optimization (NIST curves) or generic a.          */
/* Cost: 4M + 4S + 1*a for a=-3, 4M + 6S + 1*a otherwise.           */
/* ---------------------------------------------------------------- */

static int ecp_double_jac(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *R,
		const struct mbedcrypto_ecp_point *P)
{
	int ret = 0;
	struct mbedcrypto_bignum *M  = &grp->scratch[0];
	struct mbedcrypto_bignum *S  = &grp->scratch[1];
	struct mbedcrypto_bignum *TT = &grp->scratch[2];
	struct mbedcrypto_bignum *U  = &grp->scratch[3];
	struct mbedcrypto_bignum *ZZ = &grp->scratch[4];
	struct mbedcrypto_bignum *S2 = &grp->scratch[5];

	if (mbedcrypto_ecp_is_infinity(P))
		return ecp_set_zero(R);

	if ((ret = ecp_scratch_init(grp)) != 0)
		return ret;

	/* S = 4 * X * Y^2 */
	if ((ret = ecp_mul_mod(grp, TT, &P->Y, &P->Y)) != 0)
		return ret;
	if ((ret = ecp_mul_mod(grp, S, &P->X, TT)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_lshift(S, 2)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, S)) != 0)
		return ret;

	/* M = 3*X^2 + a*Z^4 */
	if (mbedcrypto_bn_cmp_word(&grp->A, -3) == 0) {
		/* a = -3: M = 3*(X+Z^2)*(X-Z^2) */
		if ((ret = ecp_mul_mod(grp, ZZ, &P->Z, &P->Z)) != 0)
			return ret;

		if ((ret = mbedcrypto_bn_add(M, &P->X, ZZ)) != 0)
			return ret;
		if ((ret = ecp_fast_mod(grp, M)) != 0)
			return ret;

		if ((ret = mbedcrypto_bn_sub(U, &P->X, ZZ)) != 0)
			return ret;
		if ((ret = mbedcrypto_bn_add(U, U, &grp->P)) != 0)
			return ret;
		if ((ret = ecp_fast_mod(grp, U)) != 0)
			return ret;

		if ((ret = ecp_mul_mod(grp, M, M, U)) != 0)
			return ret;
		if ((ret = ecp_mul_int_mod(grp, M, M, 3)) != 0)
			return ret;
	} else {
		/* Generic a: M = 3*X^2 + a*Z^4 */
		if ((ret = ecp_mul_mod(grp, M, &P->X, &P->X)) != 0)
			return ret;
		if ((ret = ecp_mul_int_mod(grp, M, M, 3)) != 0)
			return ret;

		if ((ret = ecp_mul_mod(grp, U, &P->Z, &P->Z)) != 0)
			return ret;
		if ((ret = ecp_mul_mod(grp, U, U, U)) != 0)
			return ret;
		if ((ret = ecp_mul_mod(grp, U, U, &grp->A)) != 0)
			return ret;
		if ((ret = mbedcrypto_bn_add(M, M, U)) != 0)
			return ret;
		if ((ret = ecp_fast_mod(grp, M)) != 0)
			return ret;
	}

	/* X' = M^2 - 2*S */
	if ((ret = ecp_mul_mod(grp, U, M, M)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(S2, S, S)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_sub(&R->X, U, S2)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(&R->X, &R->X, &grp->P)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(&R->X, &R->X, &grp->P)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, &R->X)) != 0)
		return ret;

	/* Z' = 2 * Y * Z  (before Y' to avoid aliasing when R == P) */
	if ((ret = ecp_mul_mod(grp, &R->Z, &P->Y, &P->Z)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_lshift(&R->Z, 1)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, &R->Z)) != 0)
		return ret;

	/* Y' = M * (S - X') - 8 * Y^4 */
	if ((ret = mbedcrypto_bn_sub(U, S, &R->X)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(U, U, &grp->P)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, U)) != 0)
		return ret;
	if ((ret = ecp_mul_mod(grp, &R->Y, M, U)) != 0)
		return ret;

	/* 8*Y^4 */
	if ((ret = ecp_mul_mod(grp, U, TT, TT)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_lshift(U, 3)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, U)) != 0)
		return ret;

	if ((ret = mbedcrypto_bn_sub(&R->Y, &R->Y, U)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(&R->Y, &R->Y, &grp->P)) != 0)
		return ret;
	return ecp_fast_mod(grp, &R->Y);
}


/* ---------------------------------------------------------------- */
/* Short-Weierstrass: Jacobian point addition                       */
/*                                                                  */
/* R = P + Q  (mixed add when Q has Z=1).                           */
/* ---------------------------------------------------------------- */

static int ecp_add_jac(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *R,
		const struct mbedcrypto_ecp_point *P,
		const struct mbedcrypto_ecp_point *Q)
{
	int ret = 0;
	int q_is_affine = 0;
	struct mbedcrypto_bignum *U1 = &grp->scratch[0];
	struct mbedcrypto_bignum *U2 = &grp->scratch[1];
	struct mbedcrypto_bignum *S1 = &grp->scratch[2];
	struct mbedcrypto_bignum *S2 = &grp->scratch[3];
	struct mbedcrypto_bignum *H  = &grp->scratch[4];
	struct mbedcrypto_bignum *HH = &grp->scratch[5];
	struct mbedcrypto_bignum *J  = &grp->scratch[6];
	struct mbedcrypto_bignum *rr = &grp->scratch[7];
	struct mbedcrypto_bignum *V  = &grp->scratch[8];

	if (mbedcrypto_ecp_is_infinity(P))
		return ecp_point_copy(R, Q);
	if (mbedcrypto_ecp_is_infinity(Q))
		return ecp_point_copy(R, P);

	if ((ret = ecp_scratch_init(grp)) != 0)
		return ret;

	/* Mixed affine-Jacobian: skip Z2 computations when Q.Z == 1 */
	q_is_affine = (mbedcrypto_bn_cmp_word(&Q->Z, 1) == 0);

	if (q_is_affine) {
		if ((ret = mbedcrypto_bn_copy(U1, &P->X)) != 0)
			return ret;
		if ((ret = mbedcrypto_bn_copy(S1, &P->Y)) != 0)
			return ret;
	} else {
		if ((ret = ecp_mul_mod(grp, U1, &Q->Z, &Q->Z)) != 0)
			return ret;
		if ((ret = ecp_mul_mod(grp, S1, U1, &Q->Z)) != 0)
			return ret;
		if ((ret = ecp_mul_mod(grp, U1, &P->X, U1)) != 0)
			return ret;
		if ((ret = ecp_mul_mod(grp, S1, &P->Y, S1)) != 0)
			return ret;
	}

	/* U2 = X2*Z1^2, S2 = Y2*Z1^3 */
	if ((ret = ecp_mul_mod(grp, U2, &P->Z, &P->Z)) != 0)
		return ret;
	if ((ret = ecp_mul_mod(grp, S2, U2, &P->Z)) != 0)
		return ret;
	if ((ret = ecp_mul_mod(grp, U2, &Q->X, U2)) != 0)
		return ret;
	if ((ret = ecp_mul_mod(grp, S2, &Q->Y, S2)) != 0)
		return ret;

	/* H = U2 - U1 */
	if ((ret = mbedcrypto_bn_sub(H, U2, U1)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(H, H, &grp->P)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, H)) != 0)
		return ret;

	/* rr = S2 - S1 */
	if ((ret = mbedcrypto_bn_sub(rr, S2, S1)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(rr, rr, &grp->P)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, rr)) != 0)
		return ret;

	/* If H == 0 */
	if (mbedcrypto_bn_cmp_word(H, 0) == 0) {
		if (mbedcrypto_bn_cmp_word(rr, 0) == 0)
			return ecp_double_jac(grp, R, P);
		else
			return ecp_set_zero(R);
	}

	/* HH = H^2 */
	if ((ret = ecp_mul_mod(grp, HH, H, H)) != 0)
		return ret;

	/* V = U1 * HH */
	if ((ret = ecp_mul_mod(grp, V, U1, HH)) != 0)
		return ret;

	/* J = H * HH (= H^3) */
	if ((ret = ecp_mul_mod(grp, J, H, HH)) != 0)
		return ret;

	/* X3 = rr^2 - J - 2*V */
	if ((ret = ecp_mul_mod(grp, &R->X, rr, rr)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_sub(&R->X, &R->X, J)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_sub(&R->X, &R->X, V)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_sub(&R->X, &R->X, V)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(&R->X, &R->X, &grp->P)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(&R->X, &R->X, &grp->P)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(&R->X, &R->X, &grp->P)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, &R->X)) != 0)
		return ret;

	/* Y3 = rr * (V - X3) - S1 * J */
	if ((ret = mbedcrypto_bn_sub(U1, V, &R->X)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(U1, U1, &grp->P)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, U1)) != 0)
		return ret;
	if ((ret = ecp_mul_mod(grp, &R->Y, rr, U1)) != 0)
		return ret;
	if ((ret = ecp_mul_mod(grp, U1, S1, J)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_sub(&R->Y, &R->Y, U1)) != 0)
		return ret;
	if ((ret = mbedcrypto_bn_add(&R->Y, &R->Y, &grp->P)) != 0)
		return ret;
	if ((ret = ecp_fast_mod(grp, &R->Y)) != 0)
		return ret;

	/* Z3 = Z1 * Z2 * H  (or Z1 * H when Q is affine) */
	if (q_is_affine)
		return ecp_mul_mod(grp, &R->Z, &P->Z, H);
	else {
		if ((ret = ecp_mul_mod(grp, &R->Z, &P->Z, &Q->Z)) != 0)
			return ret;
		return ecp_mul_mod(grp, &R->Z, &R->Z, H);
	}
}


/* ---------------------------------------------------------------- */
/* Jacobian to Affine conversion                                    */
/* ---------------------------------------------------------------- */

static int ecp_normalize_jac(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *pt)
{
	int ret = 0;
	struct mbedcrypto_bignum Zi, ZZi;

	if (mbedcrypto_ecp_is_infinity(pt))
		return 0;

	mbedcrypto_bn_init(&Zi);
	mbedcrypto_bn_init(&ZZi);

	/* Zi = Z^(-1) mod P */
	if ((ret = mbedcrypto_bn_modinv(&Zi, &pt->Z, &grp->P)) != 0)
		goto cleanup;

	/* ZZi = Zi^2 */
	if ((ret = mbedcrypto_bn_mul(&ZZi, &Zi, &Zi)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &ZZi)) != 0)
		goto cleanup;

	/* X = X * Zi^2 */
	if ((ret = mbedcrypto_bn_mul(&pt->X, &pt->X, &ZZi)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &pt->X)) != 0)
		goto cleanup;

	/* Y = Y * Zi^3 */
	if ((ret = mbedcrypto_bn_mul(&ZZi, &ZZi, &Zi)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &ZZi)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mul(&pt->Y, &pt->Y, &ZZi)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &pt->Y)) != 0)
		goto cleanup;

	/* Z = 1 */
	ret = mbedcrypto_bn_set_word(&pt->Z, 1);

cleanup:
	mbedcrypto_bn_cleanup(&Zi);
	mbedcrypto_bn_cleanup(&ZZi);
	return ret;
}


/* ---------------------------------------------------------------- */
/* Coordinate randomization for side-channel resistance             */
/* (X:Y:Z) -> (l^2*X : l^3*Y : l*Z) with random l                */
/* ---------------------------------------------------------------- */

static int ecp_randomize_coords(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *pt,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;
	struct mbedcrypto_bignum l, ll, lll;

	mbedcrypto_bn_init(&l);
	mbedcrypto_bn_init(&ll);
	mbedcrypto_bn_init(&lll);

	do {
		ret = mbedcrypto_bn_random(&l,
				(grp->pbits + 7) / 8, f_rng, p_rng);
		if (ret != 0)
			goto cleanup;
		if (mbedcrypto_bn_cmp(&l, &grp->P) >= 0) {
			if ((ret = mbedcrypto_bn_mod(&l, &l, &grp->P)) != 0)
				goto cleanup;
		}
	} while (mbedcrypto_bn_cmp_word(&l, 1) <= 0);

	if ((ret = mbedcrypto_bn_mul(&ll, &l, &l)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &ll)) != 0)
		goto cleanup;

	if ((ret = mbedcrypto_bn_mul(&lll, &ll, &l)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &lll)) != 0)
		goto cleanup;

	if ((ret = mbedcrypto_bn_mul(&pt->X, &pt->X, &ll)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &pt->X)) != 0)
		goto cleanup;

	if ((ret = mbedcrypto_bn_mul(&pt->Y, &pt->Y, &lll)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &pt->Y)) != 0)
		goto cleanup;

	if ((ret = mbedcrypto_bn_mul(&pt->Z, &pt->Z, &l)) != 0)
		goto cleanup;
	ret = ecp_fast_mod(grp, &pt->Z);

cleanup:
	mbedcrypto_bn_cleanup(&l);
	mbedcrypto_bn_cleanup(&ll);
	mbedcrypto_bn_cleanup(&lll);
	return ret;
}

/* ---------------------------------------------------------------- */
/* Batch normalization using Montgomery's trick (single inversion)  */
/* ---------------------------------------------------------------- */

/*
 * Convert an array of Jacobian points to affine using only one
 * modular inversion plus 3*(n-1) multiplications.  All points
 * must have Z != 0.
 */
static int ecp_normalize_jac_many(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *pts, size_t len)
{
	int ret = 0;
	size_t i = 0;
	struct mbedcrypto_bignum *c, inv, t, zi2;

	if (len == 0)
		return 0;
	if (len == 1)
		return ecp_normalize_jac(grp, &pts[0]);

	c = calloc(len, sizeof(*c));
	if (!c)
		return -ENOMEM;

	mbedcrypto_bn_init(&inv);
	mbedcrypto_bn_init(&t);
	mbedcrypto_bn_init(&zi2);
	for (i = 0; i < len; i++)
		mbedcrypto_bn_init(&c[i]);

	/* Forward pass: c[i] = Z[0] * Z[1] * ... * Z[i] */
	if ((ret = mbedcrypto_bn_copy(&c[0], &pts[0].Z)) != 0)
		goto cleanup;
	for (i = 1; i < len; i++) {
		if ((ret = mbedcrypto_bn_mul(&c[i], &c[i - 1], &pts[i].Z)) != 0)
			goto cleanup;
		if ((ret = ecp_fast_mod(grp, &c[i])) != 0)
			goto cleanup;
	}

	/* Single inversion: inv = (Z[0]*...*Z[n-1])^{-1} */
	if ((ret = mbedcrypto_bn_modinv(&inv, &c[len - 1], &grp->P)) != 0)
		goto cleanup;

	/* Backward pass: recover each Z[i]^{-1} and apply */
	for (i = len; i > 0; i--) {
		size_t k = i - 1;

		/* t = Z[k]^{-1} */
		if (k > 0) {
			if ((ret = mbedcrypto_bn_mul(&t, &c[k - 1], &inv)) != 0)
				goto cleanup;
			if ((ret = ecp_fast_mod(grp, &t)) != 0)
				goto cleanup;
		} else {
			if ((ret = mbedcrypto_bn_copy(&t, &inv)) != 0)
				goto cleanup;
		}

		/* Update inv for next iteration (uses original Z[k]) */
		if ((ret = mbedcrypto_bn_mul(&inv, &inv, &pts[k].Z)) != 0)
			goto cleanup;
		if ((ret = ecp_fast_mod(grp, &inv)) != 0)
			goto cleanup;

		/* X = X * t^2, Y = Y * t^3, Z = 1 */
		if ((ret = mbedcrypto_bn_mul(&zi2, &t, &t)) != 0)
			goto cleanup;
		if ((ret = ecp_fast_mod(grp, &zi2)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_mul(&pts[k].X, &pts[k].X, &zi2)) != 0)
			goto cleanup;
		if ((ret = ecp_fast_mod(grp, &pts[k].X)) != 0)
			goto cleanup;

		if ((ret = mbedcrypto_bn_mul(&zi2, &zi2, &t)) != 0)
			goto cleanup;
		if ((ret = ecp_fast_mod(grp, &zi2)) != 0)
			goto cleanup;
		if ((ret = mbedcrypto_bn_mul(&pts[k].Y, &pts[k].Y, &zi2)) != 0)
			goto cleanup;
		if ((ret = ecp_fast_mod(grp, &pts[k].Y)) != 0)
			goto cleanup;

		if ((ret = mbedcrypto_bn_set_word(&pts[k].Z, 1)) != 0)
			goto cleanup;
	}

cleanup:
	for (i = 0; i < len; i++)
		mbedcrypto_bn_cleanup(&c[i]);
	mbedcrypto_bn_cleanup(&inv);
	mbedcrypto_bn_cleanup(&t);
	mbedcrypto_bn_cleanup(&zi2);
	free(c);
	return ret;
}

/* ---------------------------------------------------------------- */
/* Fixed-base comb method for scalar multiplication                 */
/* ---------------------------------------------------------------- */

#define ECP_COMB_W 5 /* window width: 2^5 = 32-entry table */

/*
 * Precompute the comb table for a fixed base point P.
 *
 * Let d = ceil(nbits / w).  Define w "row generators":
 *   G[j] = 2^(j*d) * P   for j = 0 .. w-1
 *
 * The table has 2^w entries:
 *   table[i] = sum of G[j] for each bit j set in i.
 *   table[0] = identity (unused during the comb loop).
 *
 * All non-identity entries are stored in affine form for
 * efficient mixed Jacobian-affine addition in the main loop.
 */
static int ecp_comb_precompute(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point **out_table,
		size_t *out_tlen,
		const struct mbedcrypto_ecp_point *P)
{
	int ret = 0;
	size_t i = 0, j = 0, k = 0;
	size_t w = ECP_COMB_W;
	size_t d = (grp->nbits + w - 1) / w;
	size_t tlen = (size_t)1 << w;
	struct mbedcrypto_ecp_point *base = NULL;
	struct mbedcrypto_ecp_point *table = NULL;

	base = calloc(w, sizeof(*base));
	table = calloc(tlen, sizeof(*table));
	if (!base || !table) {
		free(base);
		free(table);
		return -ENOMEM;
	}

	for (i = 0; i < w; i++)
		mbedcrypto_ecp_point_init(&base[i]);
	for (i = 0; i < tlen; i++)
		mbedcrypto_ecp_point_init(&table[i]);

	/* base[0] = P */
	if ((ret = ecp_point_copy(&base[0], P)) != 0)
		goto cleanup;

	/* base[j] = 2^d * base[j-1]  (d repeated doublings) */
	for (j = 1; j < w; j++) {
		if ((ret = ecp_point_copy(&base[j], &base[j - 1])) != 0)
			goto cleanup;
		for (k = 0; k < d; k++) {
			if ((ret = ecp_double_jac(grp, &base[j], &base[j])) != 0)
				goto cleanup;
		}
	}

	/* Batch-normalize bases to affine */
	if ((ret = ecp_normalize_jac_many(grp, base, w)) != 0)
		goto cleanup;

	/* table[0] = identity */
	if ((ret = ecp_set_zero(&table[0])) != 0)
		goto cleanup;

	/* Build table[i] = sum of base[j] for each set bit j in i. */
	for (i = 1; i < tlen; i++) {
		/* Find lowest set bit */
		size_t low = 0;

		while (((i >> low) & 1) == 0)
			low++;

		k = i ^ ((size_t)1 << low); /* i without the lowest bit */

		if (k == 0) {
			/* Single bit set: just copy base[low] */
			if ((ret = ecp_point_copy(&table[i], &base[low])) != 0)
				goto cleanup;
		} else {
			/* table[i] = table[k] + base[low] (mixed add) */
			if ((ret = ecp_add_jac(grp, &table[i],
					&table[k], &base[low])) != 0)
				goto cleanup;
		}
	}

	/* Batch-normalize table[1..tlen-1] to affine */
	if ((ret = ecp_normalize_jac_many(grp, &table[1], tlen - 1)) != 0)
		goto cleanup;

	*out_table = table;
	*out_tlen = tlen;
	table = NULL; /* prevent cleanup from freeing */

cleanup:
	for (i = 0; i < w; i++)
		mbedcrypto_ecp_point_cleanup(&base[i]);
	free(base);

	if (table) {
		for (i = 0; i < tlen; i++)
			mbedcrypto_ecp_point_cleanup(&table[i]);
		free(table);
	}
	return ret;
}

/*
 * Comb scalar multiplication using a precomputed affine table.
 *
 * Scans the scalar m in d columns (MSB to LSB).  Each column is a
 * w-bit index formed by interleaving one bit from each of the w rows.
 *
 * Column j (0 <= j < d):
 *   col = bit(m,j) | bit(m,j+d)<<1 | ... | bit(m,j+(w-1)*d)<<(w-1)
 *
 * Total cost: d-1 doublings + at most d mixed additions.
 */
static int ecp_mul_comb(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *R,
		const struct mbedcrypto_bignum *m,
		const struct mbedcrypto_ecp_point *table,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;
	size_t j = 0, r = 0;
	size_t w = ECP_COMB_W;
	size_t d = (grp->nbits + w - 1) / w;
	int started = 0;
	struct mbedcrypto_ecp_point T;

	mbedcrypto_ecp_point_init(&T);

	for (j = d; j > 0; j--) {
		/* Double (skip until first non-zero column) */
		if (started) {
			if ((ret = ecp_double_jac(grp, &T, &T)) != 0)
				goto cleanup;
		}

		/* Extract column j-1 */
		size_t col = 0;

		for (r = 0; r < w; r++) {
			size_t bit_pos = (j - 1) + r * d;

			if (mbedcrypto_bn_test_bit(m, bit_pos))
				col |= (size_t)1 << r;
		}

		if (col == 0)
			continue;

		if (!started) {
			/* First non-zero column: copy from table */
			if ((ret = ecp_point_copy(&T, &table[col])) != 0)
				goto cleanup;

			if (f_rng) {
				if ((ret = ecp_randomize_coords(grp, &T,
						f_rng, p_rng)) != 0)
					goto cleanup;
			}
			started = 1;
		} else {
			/* Mixed affine-Jacobian addition */
			if ((ret = ecp_add_jac(grp, &T, &T, &table[col])) != 0)
				goto cleanup;
		}
	}

	if (!started) {
		ret = ecp_set_zero(R);
		goto cleanup;
	}

	/* Normalize to affine */
	if ((ret = ecp_normalize_jac(grp, &T)) != 0)
		goto cleanup;

	ret = ecp_point_copy(R, &T);

cleanup:
	mbedcrypto_ecp_point_cleanup(&T);
	return ret;
}

/* ---------------------------------------------------------------- */
/* w-NAF computation for scalar multiplication                     */
/* ---------------------------------------------------------------- */

static int ecp_compute_naf(int8_t *naf, size_t *naf_len,
		const struct mbedcrypto_bignum *k, int w)
{
	struct mbedcrypto_bignum K;
	int ret = 0;
	size_t i = 0;
	int half = 1 << (w - 1);
	int full = 1 << w;
	bn_word_t mask = (bn_word_t)(full - 1);

	mbedcrypto_bn_init(&K);
	if ((ret = mbedcrypto_bn_copy(&K, k)) != 0)
		goto out;

	while (mbedcrypto_bn_cmp_word(&K, 0) > 0) {
		if (K.data[0] & 1) {
			int val = K.data[0] & mask;
			if (val >= half)
				val -= full;
			naf[i] = (int8_t)val;
			if ((ret = mbedcrypto_bn_add_word(&K, &K, -val)) != 0)
				goto out;
		} else
			naf[i] = 0;
		if ((ret = mbedcrypto_bn_rshift(&K, 1)) != 0)
			goto out;
		i++;
	}

	*naf_len = i;
out:
	mbedcrypto_bn_cleanup(&K);
	return ret;
}

/* ---------------------------------------------------------------- */
/* Reusable scratch temporaries for ECP hot path.                   */
/*                                                                  */
/* Eliminates calloc/free overhead in point doubling and addition   */
/* by reusing pre-allocated bignums from grp->scratch[].            */
/*   scratch[0..5] - ecp_double_jac temps (M, S, TT, U, ZZ, S2)    */
/*   scratch[0..8] - ecp_add_jac temps (overlaps; safe at goto)     */
/*   scratch[9]    - product temp for bn_mul_ext                    */
/* ---------------------------------------------------------------- */


/*
 * Constant-time conditional swap of two bignums.
 * If cond is non-zero, swap a and b; otherwise no-op.
 * Operates on the raw struct bytes to swap pointers, size, sign etc.
 */
static void bn_ct_cond_swap(struct mbedcrypto_bignum *a,
		struct mbedcrypto_bignum *b, size_t cond)
{
	volatile char *pa = (volatile char *)a;
	volatile char *pb = (volatile char *)b;
	size_t mask = (size_t)0 - (size_t)(cond & 1);
	char tmp;
	size_t i = 0;

	for (i = 0; i < sizeof(*a); i++) {
		tmp = (pa[i] ^ pb[i]) & (char)mask;
		pa[i] ^= tmp;
		pb[i] ^= tmp;
	}
}


/* ---------------------------------------------------------------- */
/* Scalar multiplication: R = m * P (double-and-add, left-to-right) */
/* ---------------------------------------------------------------- */

int mbedcrypto_ecp_scalar_mul(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *R,
		const struct mbedcrypto_bignum *m,
		const struct mbedcrypto_ecp_point *P,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;
	size_t i = 0, nbits = 0;

	if (grp->type == MBEDCRYPTO_ECP_TYPE_MONTGOMERY) {
		/* Montgomery ladder for Curve25519, X-only arithmetic. */
		struct mbedcrypto_bignum x2, z2, x3, z3, t0, t1, da, cb;
		size_t b = 0;

		mbedcrypto_bn_init(&x2); mbedcrypto_bn_init(&z2);
		mbedcrypto_bn_init(&x3); mbedcrypto_bn_init(&z3);
		mbedcrypto_bn_init(&t0); mbedcrypto_bn_init(&t1);
		mbedcrypto_bn_init(&da); mbedcrypto_bn_init(&cb);

		/* (x2:z2) = (1:0) = point at infinity */
		if ((ret = mbedcrypto_bn_set_word(&x2, 1)) != 0)
			goto m_cleanup;
		if ((ret = mbedcrypto_bn_set_word(&z2, 0)) != 0)
			goto m_cleanup;

		/* (x3:z3) = (Px:1) = P */
		if ((ret = mbedcrypto_bn_copy(&x3, &P->X)) != 0)
			goto m_cleanup;
		if ((ret = mbedcrypto_bn_set_word(&z3, 1)) != 0)
			goto m_cleanup;

		nbits = grp->pbits;

		for (i = nbits; i > 0; i--) {
			b = mbedcrypto_bn_test_bit(m, i - 1);

			/* Constant-time conditional swap */
			bn_ct_cond_swap(&x2, &x3, b);
			bn_ct_cond_swap(&z2, &z3, b);

			/* Montgomery differential addition + doubling */
			/* t0 = x2 + z2 */
			if ((ret = mbedcrypto_bn_add(&t0, &x2, &z2)) != 0)
				goto m_cleanup;
			if ((ret = ecp_fast_mod(grp, &t0)) != 0)
				goto m_cleanup;
			/* t1 = x2 - z2 */
			if ((ret = mbedcrypto_bn_sub(&t1, &x2, &z2)) != 0)
				goto m_cleanup;
			if ((ret = mbedcrypto_bn_add(&t1, &t1, &grp->P)) != 0)
				goto m_cleanup;
			if ((ret = ecp_fast_mod(grp, &t1)) != 0)
				goto m_cleanup;

			/* x2 = (x3-z3)*(x2+z2) */
			if ((ret = mbedcrypto_bn_sub(&da, &x3, &z3)) != 0)
				goto m_cleanup;
			if ((ret = mbedcrypto_bn_add(&da, &da, &grp->P)) != 0)
				goto m_cleanup;
			if ((ret = mbedcrypto_bn_mul(&da, &da, &t0)) != 0)
				goto m_cleanup;
			if ((ret = ecp_fast_mod(grp, &da)) != 0)
				goto m_cleanup;

			if ((ret = mbedcrypto_bn_add(&cb, &x3, &z3)) != 0)
				goto m_cleanup;
			if ((ret = mbedcrypto_bn_mul(&cb, &cb, &t1)) != 0)
				goto m_cleanup;
			if ((ret = ecp_fast_mod(grp, &cb)) != 0)
				goto m_cleanup;

			/* x3 = (da+cb)^2 */
			if ((ret = mbedcrypto_bn_add(&x3, &da, &cb)) != 0)
				goto m_cleanup;
			if ((ret = mbedcrypto_bn_mul(&x3, &x3, &x3)) != 0)
				goto m_cleanup;
			if ((ret = ecp_fast_mod(grp, &x3)) != 0)
				goto m_cleanup;

			/* z3 = Px * (da-cb)^2 */
			if ((ret = mbedcrypto_bn_sub(&z3, &da, &cb)) != 0)
				goto m_cleanup;
			if ((ret = mbedcrypto_bn_add(&z3, &z3, &grp->P)) != 0)
				goto m_cleanup;
			if ((ret = mbedcrypto_bn_mul(&z3, &z3, &z3)) != 0)
				goto m_cleanup;
			if ((ret = ecp_fast_mod(grp, &z3)) != 0)
				goto m_cleanup;
			if ((ret = mbedcrypto_bn_mul(&z3, &z3, &P->X)) != 0)
				goto m_cleanup;
			if ((ret = ecp_fast_mod(grp, &z3)) != 0)
				goto m_cleanup;

			/* Doubling: (x2:z2) = 2*(x2:z2) */
			{
				struct mbedcrypto_bignum aa, bb, e, cc;
				mbedcrypto_bn_init(&aa); mbedcrypto_bn_init(&bb);
				mbedcrypto_bn_init(&e);  mbedcrypto_bn_init(&cc);

				/* aa = t0^2 = (x2+z2)^2 */
				if ((ret = mbedcrypto_bn_mul(&aa, &t0, &t0)) != 0)
					goto dbl_cleanup;
				if ((ret = ecp_fast_mod(grp, &aa)) != 0)
					goto dbl_cleanup;

				/* bb = t1^2 = (x2-z2)^2 */
				if ((ret = mbedcrypto_bn_mul(&bb, &t1, &t1)) != 0)
					goto dbl_cleanup;
				if ((ret = ecp_fast_mod(grp, &bb)) != 0)
					goto dbl_cleanup;

				/* e = aa - bb */
				if ((ret = mbedcrypto_bn_sub(&e, &aa, &bb)) != 0)
					goto dbl_cleanup;
				if ((ret = mbedcrypto_bn_add(&e, &e, &grp->P)) != 0)
					goto dbl_cleanup;
				if ((ret = ecp_fast_mod(grp, &e)) != 0)
					goto dbl_cleanup;

				/* x2 = aa * bb */
				if ((ret = mbedcrypto_bn_mul(&x2, &aa, &bb)) != 0)
					goto dbl_cleanup;
				if ((ret = ecp_fast_mod(grp, &x2)) != 0)
					goto dbl_cleanup;

				/* z2 = e * (bb + (A+2)/4 * e) */
				/* (A+2)/4 = (486662+2)/4 = 121666 */
				if ((ret = mbedcrypto_bn_mul_word(&cc, &e, 121666)) != 0)
					goto dbl_cleanup;
				if ((ret = ecp_fast_mod(grp, &cc)) != 0)
					goto dbl_cleanup;
				if ((ret = mbedcrypto_bn_add(&cc, &cc, &bb)) != 0)
					goto dbl_cleanup;
				if ((ret = ecp_fast_mod(grp, &cc)) != 0)
					goto dbl_cleanup;
				if ((ret = mbedcrypto_bn_mul(&z2, &e, &cc)) != 0)
					goto dbl_cleanup;
				ret = ecp_fast_mod(grp, &z2);

dbl_cleanup:
				mbedcrypto_bn_cleanup(&aa); mbedcrypto_bn_cleanup(&bb);
				mbedcrypto_bn_cleanup(&e);  mbedcrypto_bn_cleanup(&cc);
				if (ret != 0)
					goto m_cleanup;
			}

			/* Constant-time conditional swap back */
			bn_ct_cond_swap(&x2, &x3, b);
			bn_ct_cond_swap(&z2, &z3, b);
		}

		/* Convert to affine: X = x2 * z2^(-1) mod P */
		if ((ret = mbedcrypto_bn_modinv(&z2, &z2, &grp->P)) != 0)
			goto m_cleanup;
		if ((ret = mbedcrypto_bn_mul(&R->X, &x2, &z2)) != 0)
			goto m_cleanup;
		if ((ret = ecp_fast_mod(grp, &R->X)) != 0)
			goto m_cleanup;
		if ((ret = mbedcrypto_bn_set_word(&R->Y, 0)) != 0)
			goto m_cleanup;
		ret = mbedcrypto_bn_set_word(&R->Z, 1);

m_cleanup:
		mbedcrypto_bn_cleanup(&x2); mbedcrypto_bn_cleanup(&z2);
		mbedcrypto_bn_cleanup(&x3); mbedcrypto_bn_cleanup(&z3);
		mbedcrypto_bn_cleanup(&t0); mbedcrypto_bn_cleanup(&t1);
		mbedcrypto_bn_cleanup(&da); mbedcrypto_bn_cleanup(&cb);
		return ret;
	}

	/*
	 * Short-Weierstrass scalar multiplication.
	 *
	 * When P is the generator, use the fixed-base comb method with a
	 * cached precomputed table (2^w affine points, w = ECP_COMB_W).
	 * This cuts the main loop to ~ceil(nbits/w) doublings + additions,
	 * roughly a 5x reduction compared to w-NAF for P-256.
	 *
	 * For other base points, fall back to w-NAF(4).
	 */
	nbits = mbedcrypto_bn_bit_count(m);
	if (nbits == 0)
		return ecp_set_zero(R);

	/* --- Fixed-base comb for generator --- */
	if (P == &grp->G) {
		/* Build table on first use, then cache in grp */
		if (!grp->gen_table) {
			ret = ecp_comb_precompute(grp, &grp->gen_table,
					&grp->gen_tlen, &grp->G);
			if (ret != 0)
				return ret;
		}
		return ecp_mul_comb(grp, R, m, grp->gen_table,
				f_rng, p_rng);
	}

	/* --- Variable-base: windowed NAF (w=4) --- */
	{
		struct mbedcrypto_ecp_point T, pre[4], dbl, neg;
		int8_t naf[522]; /* max 521+1 for secp521r1 */
		size_t naf_len = 0, j;

		mbedcrypto_ecp_point_init(&T);
		mbedcrypto_ecp_point_init(&dbl);
		mbedcrypto_ecp_point_init(&neg);
		for (j = 0; j < 4; j++)
			mbedcrypto_ecp_point_init(&pre[j]);

		memset(naf, 0, sizeof(naf));
		if ((ret = ecp_compute_naf(naf, &naf_len, m, 4)) != 0)
			goto sw_cleanup;

		/* pre[0] = P */
		if ((ret = ecp_point_copy(&pre[0], P)) != 0)
			goto sw_cleanup;

		/* dbl = 2P */
		if ((ret = ecp_double_jac(grp, &dbl, P)) != 0)
			goto sw_cleanup;

		/* pre[i] = (2i+1)*P -> 3P, 5P, 7P */
		for (j = 1; j < 4; j++) {
			if ((ret = ecp_add_jac(grp, &pre[j], &pre[j - 1], &dbl)) != 0)
				goto sw_cleanup;
		}

		/* Normalize to affine (Z=1) for mixed addition */
		for (j = 0; j < 4; j++) {
			if ((ret = ecp_normalize_jac(grp, &pre[j])) != 0)
				goto sw_cleanup;
		}

		/* Find the most significant non-zero NAF digit */
		i = naf_len;
		while (i > 0 && naf[i - 1] == 0)
			i--;

		if (i == 0) {
			ret = ecp_set_zero(R);
			goto sw_cleanup;
		}

		/* Initialize accumulator T from MSB non-zero digit */
		{
			int d = naf[i - 1];
			int idx = ((d > 0 ? d : -d) - 1) / 2;

			if ((ret = ecp_point_copy(&T, &pre[idx])) != 0)
				goto sw_cleanup;
			if (d < 0) {
				if ((ret = mbedcrypto_bn_sub(&T.Y, &grp->P, &T.Y)) != 0)
					goto sw_cleanup;
			}
		}
		i--;

		/* Coordinate randomization for side-channel protection */
		if (f_rng) {
			if ((ret = ecp_randomize_coords(grp, &T, f_rng, p_rng)) != 0)
				goto sw_cleanup;
		}

		/* Main loop: double and conditional mixed add/subtract */
		for (; i > 0; i--) {
			if ((ret = ecp_double_jac(grp, &T, &T)) != 0)
				goto sw_cleanup;

			if (naf[i - 1] > 0) {
				int idx = (naf[i - 1] - 1) / 2;

				if ((ret = ecp_add_jac(grp, &T, &T, &pre[idx])) != 0)
					goto sw_cleanup;
			} else if (naf[i - 1] < 0) {
				int idx = (-naf[i - 1] - 1) / 2;

				if ((ret = ecp_point_copy(&neg, &pre[idx])) != 0)
					goto sw_cleanup;
				ret = mbedcrypto_bn_sub(&neg.Y, &grp->P,
						&pre[idx].Y);
				if (ret != 0)
					goto sw_cleanup;
				if ((ret = ecp_add_jac(grp, &T, &T, &neg)) != 0)
					goto sw_cleanup;
			}
		}

		/* Normalize result to affine */
		if ((ret = ecp_normalize_jac(grp, &T)) != 0)
			goto sw_cleanup;

		ret = ecp_point_copy(R, &T);

sw_cleanup:
		mbedcrypto_ecp_point_cleanup(&T);
		mbedcrypto_ecp_point_cleanup(&dbl);
		mbedcrypto_ecp_point_cleanup(&neg);
		for (j = 0; j < 4; j++)
			mbedcrypto_ecp_point_cleanup(&pre[j]);
		return ret;
	}
}

/* ---------------------------------------------------------------- */
/* Dual scalar multiplication: R = m*P + n*Q  (Shamir's trick)      */
/* ---------------------------------------------------------------- */

int mbedcrypto_ecp_dual_scalar_mul(struct mbedcrypto_ecp_group *grp,
		struct mbedcrypto_ecp_point *R,
		const struct mbedcrypto_bignum *m,
		const struct mbedcrypto_ecp_point *P,
		const struct mbedcrypto_bignum *n,
		const struct mbedcrypto_ecp_point *Q)
{
	int ret = 0;
	size_t i = 0, len_m = 0, len_n = 0, len = 0;
	struct mbedcrypto_ecp_point T, PQ;  /* PQ = P + Q */

	mbedcrypto_ecp_point_init(&T);
	mbedcrypto_ecp_point_init(&PQ);

	/* Precompute P + Q */
	if ((ret = ecp_add_jac(grp, &PQ, P, Q)) != 0)
		goto cleanup;
	if ((ret = ecp_normalize_jac(grp, &PQ)) != 0)
		goto cleanup;

	len_m = mbedcrypto_bn_bit_count(m);
	len_n = mbedcrypto_bn_bit_count(n);
	len = (len_m > len_n) ? len_m : len_n;

	/* Start with infinity */
	if ((ret = ecp_set_zero(&T)) != 0)
		goto cleanup;

	for (i = len; i > 0; i--) {
		int bm = mbedcrypto_bn_test_bit(m, i - 1);
		int bn = mbedcrypto_bn_test_bit(n, i - 1);

		if ((ret = ecp_double_jac(grp, &T, &T)) != 0)
			goto cleanup;

		if (bm && bn)
			ret = ecp_add_jac(grp, &T, &T, &PQ);
		else if (bm)
			ret = ecp_add_jac(grp, &T, &T, P);
		else if (bn)
			ret = ecp_add_jac(grp, &T, &T, Q);

		if (ret != 0)
			goto cleanup;
	}

	if ((ret = ecp_normalize_jac(grp, &T)) != 0)
		goto cleanup;

	ret = ecp_point_copy(R, &T);

cleanup:
	mbedcrypto_ecp_point_cleanup(&T);
	mbedcrypto_ecp_point_cleanup(&PQ);
	return ret;
}

/* ---------------------------------------------------------------- */
/* Check that a point is on the curve                               */
/* ---------------------------------------------------------------- */

int mbedcrypto_ecp_validate_point(struct mbedcrypto_ecp_group *grp,
		const struct mbedcrypto_ecp_point *pt)
{
	int ret = 0;
	struct mbedcrypto_bignum YY, RHS, AX;

	if (grp->type == MBEDCRYPTO_ECP_TYPE_MONTGOMERY) {
		/* Just check 0 <= X < P */
		if (mbedcrypto_bn_cmp_word(&pt->X, 0) < 0 ||
		    mbedcrypto_bn_cmp(&pt->X, &grp->P) >= 0)
			return -EINVAL;
		return 0;
	}

	/* Short-Weierstrass: check y^2 = x^3 + ax + b (mod P) */
	mbedcrypto_bn_init(&YY);
	mbedcrypto_bn_init(&RHS);
	mbedcrypto_bn_init(&AX);

	/* YY = Y^2 mod P */
	if ((ret = mbedcrypto_bn_mul(&YY, &pt->Y, &pt->Y)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &YY)) != 0)
		goto cleanup;

	/* RHS = X^3 + aX + b mod P */
	if ((ret = mbedcrypto_bn_mul(&RHS, &pt->X, &pt->X)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &RHS)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mul(&RHS, &RHS, &pt->X)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &RHS)) != 0)
		goto cleanup;

	/* + aX */
	if ((ret = mbedcrypto_bn_mul(&AX, &grp->A, &pt->X)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &AX)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_add(&RHS, &RHS, &AX)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &RHS)) != 0)
		goto cleanup;

	/* + b */
	if ((ret = mbedcrypto_bn_add(&RHS, &RHS, &grp->B)) != 0)
		goto cleanup;
	if ((ret = ecp_fast_mod(grp, &RHS)) != 0)
		goto cleanup;

	if (mbedcrypto_bn_cmp(&YY, &RHS) != 0)
		ret = -EINVAL;
	else
		ret = 0;

cleanup:
	mbedcrypto_bn_cleanup(&YY);
	mbedcrypto_bn_cleanup(&RHS);
	mbedcrypto_bn_cleanup(&AX);
	return ret;
}

/* ---------------------------------------------------------------- */
/* Key generation                                                   */
/* ---------------------------------------------------------------- */

int mbedcrypto_ecp_keygen(int grp_id,
		struct mbedcrypto_ecp_keypair *key,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret, count = 0;
	size_t i = 0, n_bytes = 0;

	if ((ret = mbedcrypto_ecp_load_group(&key->grp, grp_id)) != 0)
		return ret;

	n_bytes = (key->grp.nbits + 7) / 8;

	if (key->grp.type == MBEDCRYPTO_ECP_TYPE_MONTGOMERY) {
		/* Curve25519/X448: clamp the scalar per RFC 7748 */
		uint8_t buf[56]; /* max: X448 = 56 bytes */

		if (n_bytes > sizeof(buf))
			return -EINVAL;

		if ((ret = f_rng(p_rng, buf, n_bytes)) != 0)
			return ret;

		/* Clamp: clear 3 lowest bits, clear bit 255, set bit 254 */
		buf[0] &= 0xF8;
		buf[n_bytes - 1] &= 0x7F;
		buf[n_bytes - 1] |= 0x40;

		/* Curve25519 scalars are little-endian in RFC 7748 */
		/* But our bignum uses big-endian read, so reverse */
		for (i = 0; i < n_bytes / 2; i++) {
			uint8_t t = buf[i];

			buf[i] = buf[n_bytes - 1 - i];
			buf[n_bytes - 1 - i] = t;
		}

		ret = mbedcrypto_bn_from_binary(&key->d, buf, n_bytes);
		memset(buf, 0, n_bytes);
		if (ret != 0)
			return ret;

		/* Q = d * G (X-only) */
		ret = mbedcrypto_ecp_scalar_mul(&key->grp, &key->Q,
				&key->d, &key->grp.G, f_rng, p_rng);
		return ret;
	}

	/* Short-Weierstrass: d in [1, N-1] */
	do {
		ret = mbedcrypto_bn_random(&key->d, n_bytes,
				f_rng, p_rng);
		if (ret != 0)
			return ret;

		if (n_bytes * 8 > key->grp.nbits) {
			ret = mbedcrypto_bn_rshift(&key->d,
					n_bytes * 8 - key->grp.nbits);
			if (ret != 0)
				return ret;
		}

		if (count++ > 30)
			return -EAGAIN;
	} while (mbedcrypto_bn_cmp(&key->d, &key->grp.N) >= 0 ||
		 mbedcrypto_bn_cmp_word(&key->d, 1) < 0);

	/* Q = d * G */
	ret = mbedcrypto_ecp_scalar_mul(&key->grp, &key->Q,
			&key->d, &key->grp.G, f_rng, p_rng);
	return ret;
}
