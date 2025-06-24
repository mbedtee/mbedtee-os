// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * DES / Triple-DES block cipher (FIPS 46-3)
 *
 * When CONFIG_MBEDCRYPTO_DES_TABLE is defined, uses combined SP
 * lookup tables (sp[8][64] = 2048 bytes) with macro-based fully
 * unrolled rounds for maximum throughput. Otherwise, uses factored
 * sbox[8][64] + ptab[8][16] = 1024 bytes with two-level lookups
 * and a compact loop.
 *
 * Warning: DES/3DES are considered weak ciphers. This is kept only
 * for GP TEE Internal API compatibility.
 */

#include <string.h>

#include <mbedcrypto/des.h>

#if defined(CONFIG_MBEDCRYPTO_DES_TABLE)
/*
 * Combined S-box + P-permutation tables. Each sp[s][i] directly
 * produces the 32-bit contribution of S-box 's' for 6-bit input 'i',
 * with bits pre-positioned for XOR accumulation. Includes the 1-bit
 * left rotation matching the des_ip/des_fp rotated representation.
 *
 * 2048 bytes total (vs 1024 for factored approach).
 */
static const uint32_t sp[8][64] = {
	/* S1 */
	{
		0x01010400, 0x00000000, 0x00010000, 0x01010404,
		0x01010004, 0x00010404, 0x00000004, 0x00010000,
		0x00000400, 0x01010400, 0x01010404, 0x00000400,
		0x01000404, 0x01010004, 0x01000000, 0x00000004,
		0x00000404, 0x01000400, 0x01000400, 0x00010400,
		0x00010400, 0x01010000, 0x01010000, 0x01000404,
		0x00010004, 0x01000004, 0x01000004, 0x00010004,
		0x00000000, 0x00000404, 0x00010404, 0x01000000,
		0x00010000, 0x01010404, 0x00000004, 0x01010000,
		0x01010400, 0x01000000, 0x01000000, 0x00000400,
		0x01010004, 0x00010000, 0x00010400, 0x01000004,
		0x00000400, 0x00000004, 0x01000404, 0x00010404,
		0x01010404, 0x00010004, 0x01010000, 0x01000404,
		0x01000004, 0x00000404, 0x00010404, 0x01010400,
		0x00000404, 0x01000400, 0x01000400, 0x00000000,
		0x00010004, 0x00010400, 0x00000000, 0x01010004
	},
	/* S2 */
	{
		0x80108020, 0x80008000, 0x00008000, 0x00108020,
		0x00100000, 0x00000020, 0x80100020, 0x80008020,
		0x80000020, 0x80108020, 0x80108000, 0x80000000,
		0x80008000, 0x00100000, 0x00000020, 0x80100020,
		0x00108000, 0x00100020, 0x80008020, 0x00000000,
		0x80000000, 0x00008000, 0x00108020, 0x80100000,
		0x00100020, 0x80000020, 0x00000000, 0x00108000,
		0x00008020, 0x80108000, 0x80100000, 0x00008020,
		0x00000000, 0x00108020, 0x80100020, 0x00100000,
		0x80008020, 0x80100000, 0x80108000, 0x00008000,
		0x80100000, 0x80008000, 0x00000020, 0x80108020,
		0x00108020, 0x00000020, 0x00008000, 0x80000000,
		0x00008020, 0x80108000, 0x00100000, 0x80000020,
		0x00100020, 0x80008020, 0x80000020, 0x00100020,
		0x00108000, 0x00000000, 0x80008000, 0x00008020,
		0x80000000, 0x80100020, 0x80108020, 0x00108000
	},
	/* S3 */
	{
		0x00000208, 0x08020200, 0x00000000, 0x08020008,
		0x08000200, 0x00000000, 0x00020208, 0x08000200,
		0x00020008, 0x08000008, 0x08000008, 0x00020000,
		0x08020208, 0x00020008, 0x08020000, 0x00000208,
		0x08000000, 0x00000008, 0x08020200, 0x00000200,
		0x00020200, 0x08020000, 0x08020008, 0x00020208,
		0x08000208, 0x00020200, 0x00020000, 0x08000208,
		0x00000008, 0x08020208, 0x00000200, 0x08000000,
		0x08020200, 0x08000000, 0x00020008, 0x00000208,
		0x00020000, 0x08020200, 0x08000200, 0x00000000,
		0x00000200, 0x00020008, 0x08020208, 0x08000200,
		0x08000008, 0x00000200, 0x00000000, 0x08020008,
		0x08000208, 0x00020000, 0x08000000, 0x08020208,
		0x00000008, 0x00020208, 0x00020200, 0x08000008,
		0x08020000, 0x08000208, 0x00000208, 0x08020000,
		0x00020208, 0x00000008, 0x08020008, 0x00020200
	},
	/* S4 */
	{
		0x00802001, 0x00002081, 0x00002081, 0x00000080,
		0x00802080, 0x00800081, 0x00800001, 0x00002001,
		0x00000000, 0x00802000, 0x00802000, 0x00802081,
		0x00000081, 0x00000000, 0x00800080, 0x00800001,
		0x00000001, 0x00002000, 0x00800000, 0x00802001,
		0x00000080, 0x00800000, 0x00002001, 0x00002080,
		0x00800081, 0x00000001, 0x00002080, 0x00800080,
		0x00002000, 0x00802080, 0x00802081, 0x00000081,
		0x00800080, 0x00800001, 0x00802000, 0x00802081,
		0x00000081, 0x00000000, 0x00000000, 0x00802000,
		0x00002080, 0x00800080, 0x00800081, 0x00000001,
		0x00802001, 0x00002081, 0x00002081, 0x00000080,
		0x00802081, 0x00000081, 0x00000001, 0x00002000,
		0x00800001, 0x00002001, 0x00802080, 0x00800081,
		0x00002001, 0x00002080, 0x00800000, 0x00802001,
		0x00000080, 0x00800000, 0x00002000, 0x00802080
	},
	/* S5 */
	{
		0x00000100, 0x02080100, 0x02080000, 0x42000100,
		0x00080000, 0x00000100, 0x40000000, 0x02080000,
		0x40080100, 0x00080000, 0x02000100, 0x40080100,
		0x42000100, 0x42080000, 0x00080100, 0x40000000,
		0x02000000, 0x40080000, 0x40080000, 0x00000000,
		0x40000100, 0x42080100, 0x42080100, 0x02000100,
		0x42080000, 0x40000100, 0x00000000, 0x42000000,
		0x02080100, 0x02000000, 0x42000000, 0x00080100,
		0x00080000, 0x42000100, 0x00000100, 0x02000000,
		0x40000000, 0x02080000, 0x42000100, 0x40080100,
		0x02000100, 0x40000000, 0x42080000, 0x02080100,
		0x40080100, 0x00000100, 0x02000000, 0x42080000,
		0x42080100, 0x00080100, 0x42000000, 0x42080100,
		0x02080000, 0x00000000, 0x40080000, 0x42000000,
		0x00080100, 0x02000100, 0x40000100, 0x00080000,
		0x00000000, 0x40080000, 0x02080100, 0x40000100
	},
	/* S6 */
	{
		0x20000010, 0x20400000, 0x00004000, 0x20404010,
		0x20400000, 0x00000010, 0x20404010, 0x00400000,
		0x20004000, 0x00404010, 0x00400000, 0x20000010,
		0x00400010, 0x20004000, 0x20000000, 0x00004010,
		0x00000000, 0x00400010, 0x20004010, 0x00004000,
		0x00404000, 0x20004010, 0x00000010, 0x20400010,
		0x20400010, 0x00000000, 0x00404010, 0x20404000,
		0x00004010, 0x00404000, 0x20404000, 0x20000000,
		0x20004000, 0x00000010, 0x20400010, 0x00404000,
		0x20404010, 0x00400000, 0x00004010, 0x20000010,
		0x00400000, 0x20004000, 0x20000000, 0x00004010,
		0x20000010, 0x20404010, 0x00404000, 0x20400000,
		0x00404010, 0x20404000, 0x00000000, 0x20400010,
		0x00000010, 0x00004000, 0x20400000, 0x00404010,
		0x00004000, 0x00400010, 0x20004010, 0x00000000,
		0x20404000, 0x20000000, 0x00400010, 0x20004010
	},
	/* S7 */
	{
		0x00200000, 0x04200002, 0x04000802, 0x00000000,
		0x00000800, 0x04000802, 0x00200802, 0x04200800,
		0x04200802, 0x00200000, 0x00000000, 0x04000002,
		0x00000002, 0x04000000, 0x04200002, 0x00000802,
		0x04000800, 0x00200802, 0x00200002, 0x04000800,
		0x04000002, 0x04200000, 0x04200800, 0x00200002,
		0x04200000, 0x00000800, 0x00000802, 0x04200802,
		0x00200800, 0x00000002, 0x04000000, 0x00200800,
		0x04000000, 0x00200800, 0x00200000, 0x04000802,
		0x04000802, 0x04200002, 0x04200002, 0x00000002,
		0x00200002, 0x04000000, 0x04000800, 0x00200000,
		0x04200800, 0x00000802, 0x00200802, 0x04200800,
		0x00000802, 0x04000002, 0x04200802, 0x04200000,
		0x00200800, 0x00000000, 0x00000002, 0x04200802,
		0x00000000, 0x00200802, 0x04200000, 0x00000800,
		0x04000002, 0x04000800, 0x00000800, 0x00200002
	},
	/* S8 */
	{
		0x10001040, 0x00001000, 0x00040000, 0x10041040,
		0x10000000, 0x10001040, 0x00000040, 0x10000000,
		0x00040040, 0x10040000, 0x10041040, 0x00041000,
		0x10041000, 0x00041040, 0x00001000, 0x00000040,
		0x10040000, 0x10000040, 0x10001000, 0x00001040,
		0x00041000, 0x00040040, 0x10040040, 0x10041000,
		0x00001040, 0x00000000, 0x00000000, 0x10040040,
		0x10000040, 0x10001000, 0x00041040, 0x00040000,
		0x00041040, 0x00040000, 0x10041000, 0x00001000,
		0x00000040, 0x10040040, 0x00001000, 0x00041040,
		0x10001000, 0x00000040, 0x10000040, 0x10040000,
		0x10040040, 0x10000000, 0x00040000, 0x10001040,
		0x00000000, 0x10041040, 0x00040040, 0x10000040,
		0x10040000, 0x10001000, 0x10001040, 0x00000000,
		0x10041040, 0x00041000, 0x00041000, 0x00001040,
		0x00001040, 0x00040040, 0x10000000, 0x10041000
	},
};

/*
 * Full-table round macro: both subkey XOR values computed up front
 * so all 8 SP lookups are fully independent -- the CPU load unit
 * can pipeline them without data-dependency stalls.  Paired with
 * full round-unrolling (no loop overhead, cross-round scheduling),
 * this makes the full-table path structurally faster than the
 * half-table loop path.
 */
#define DES_ROUND(l, r, sk) do {                                \
	uint32_t _t0 = (sk)[0] ^ (r);                            \
	uint32_t _t1 = (sk)[1] ^ (((r) << 28) | ((r) >> 4));    \
	(l) ^= sp[7][_t0 & 0x3F]                                \
	     ^ sp[5][(_t0 >>  8) & 0x3F]                        \
	     ^ sp[3][(_t0 >> 16) & 0x3F]                        \
	     ^ sp[1][(_t0 >> 24) & 0x3F]                        \
	     ^ sp[6][_t1 & 0x3F]                                \
	     ^ sp[4][(_t1 >>  8) & 0x3F]                        \
	     ^ sp[2][(_t1 >> 16) & 0x3F]                        \
	     ^ sp[0][(_t1 >> 24) & 0x3F];                       \
} while (0)

#else /* !CONFIG_MBEDCRYPTO_DES_TABLE */

/*
 * Raw S-box tables. Each sbox[s][i] maps a 6-bit input to
 * a 4-bit output per FIPS 46-3.
 *
 * 512 bytes.
 */
static const uint8_t sbox[8][64] = {
	/* S1 */
	{
		14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
		 3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
		 4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
		15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13
	},
	/* S2 */
	{
		15, 10,  2,  7,  4,  1, 13, 11,  9, 15, 14,  8, 10,  4,  1, 13,
		 6,  5, 11,  0,  8,  2,  7, 12,  5,  9,  0,  6,  3, 14, 12,  3,
		 0,  7, 13,  4, 11, 12, 14,  2, 12, 10,  1, 15,  7,  1,  2,  8,
		 3, 14,  4,  9,  5, 11,  9,  5,  6,  0, 10,  3,  8, 13, 15,  6
	},
	/* S3 */
	{
		 3, 14,  0, 13, 10,  0,  7, 10,  5,  9,  9,  4, 15,  5, 12,  3,
		 8,  1, 14,  2,  6, 12, 13,  7, 11,  6,  4, 11,  1, 15,  2,  8,
		14,  8,  5,  3,  4, 14, 10,  0,  2,  5, 15, 10,  9,  2,  0, 13,
		11,  4,  8, 15,  1,  7,  6,  9, 12, 11,  3, 12,  7,  1, 13,  6
	},
	/* S4 */
	{
		13,  7,  7,  2, 14, 11,  9,  5,  0, 12, 12, 15,  3,  0, 10,  9,
		 1,  4,  8, 13,  2,  8,  5,  6, 11,  1,  6, 10,  4, 14, 15,  3,
		10,  9, 12, 15,  3,  0,  0, 12,  6, 10, 11,  1, 13,  7,  7,  2,
		15,  3,  1,  4,  9,  5, 14, 11,  5,  6,  8, 13,  2,  8,  4, 14
	},
	/* S5 */
	{
		 1,  7,  6, 13,  2,  1,  8,  6, 11,  2,  5, 11, 13, 14,  3,  8,
		 4, 10, 10,  0,  9, 15, 15,  5, 14,  9,  0, 12,  7,  4, 12,  3,
		 2, 13,  1,  4,  8,  6, 13, 11,  5,  8, 14,  7, 11,  1,  4, 14,
		15,  3, 12, 15,  6,  0, 10, 12,  3,  5,  9,  2,  0, 10,  7,  9
	},
	/* S6 */
	{
		 9, 12,  2, 15, 12,  1, 15,  4, 10,  7,  4,  9,  5, 10,  8,  3,
		 0,  5, 11,  2,  6, 11,  1, 13, 13,  0,  7, 14,  3,  6, 14,  8,
		10,  1, 13,  6, 15,  4,  3,  9,  4, 10,  8,  3,  9, 15,  6, 12,
		 7, 14,  0, 13,  1,  2, 12,  7,  2,  5, 11,  0, 14,  8,  5, 11
	},
	/* S7 */
	{
		 4, 13, 11,  0,  2, 11,  7, 14, 15,  4,  0,  9,  1,  8, 13,  3,
		10,  7,  5, 10,  9, 12, 14,  5, 12,  2,  3, 15,  6,  1,  8,  6,
		 8,  6,  4, 11, 11, 13, 13,  1,  5,  8, 10,  4, 14,  3,  7, 14,
		 3,  9, 15, 12,  6,  0,  1, 15,  0,  7, 12,  2,  9, 10,  2,  5
	},
	/* S8 */
	{
		11,  2,  4, 15,  8, 11,  1,  8,  5, 12, 15,  6, 14,  7,  2,  1,
		12,  9, 10,  3,  6,  5, 13, 14,  3,  0,  0, 13,  9, 10,  7,  4,
		 7,  4, 14,  2,  1, 13,  2,  7, 10,  1,  9, 12, 13,  8,  4, 11,
		 0, 15,  5,  9, 12, 10, 11,  0, 15,  6,  6,  3,  3,  5,  8, 14
	},
};

/*
 * P-permutation contribution tables. ptab[s][v] gives the 32-bit
 * word for S-box 's' producing 4-bit output value 'v', with bits
 * pre-positioned for direct XOR accumulation. Includes the 1-bit
 * left rotation matching the des_ip/des_fp rotated representation.
 *
 * 512 bytes. Combined with sbox[]: 1024 bytes total (vs 2048).
 */
static const uint32_t ptab[8][16] = {
	/* S1 */
	{
		0x00000000, 0x00000004, 0x00000400, 0x00000404,
		0x00010000, 0x00010004, 0x00010400, 0x00010404,
		0x01000000, 0x01000004, 0x01000400, 0x01000404,
		0x01010000, 0x01010004, 0x01010400, 0x01010404
	},
	/* S2 */
	{
		0x00000000, 0x00000020, 0x00008000, 0x00008020,
		0x00100000, 0x00100020, 0x00108000, 0x00108020,
		0x80000000, 0x80000020, 0x80008000, 0x80008020,
		0x80100000, 0x80100020, 0x80108000, 0x80108020
	},
	/* S3 */
	{
		0x00000000, 0x00000008, 0x00000200, 0x00000208,
		0x00020000, 0x00020008, 0x00020200, 0x00020208,
		0x08000000, 0x08000008, 0x08000200, 0x08000208,
		0x08020000, 0x08020008, 0x08020200, 0x08020208
	},
	/* S4 */
	{
		0x00000000, 0x00000001, 0x00000080, 0x00000081,
		0x00002000, 0x00002001, 0x00002080, 0x00002081,
		0x00800000, 0x00800001, 0x00800080, 0x00800081,
		0x00802000, 0x00802001, 0x00802080, 0x00802081
	},
	/* S5 */
	{
		0x00000000, 0x00000100, 0x00080000, 0x00080100,
		0x02000000, 0x02000100, 0x02080000, 0x02080100,
		0x40000000, 0x40000100, 0x40080000, 0x40080100,
		0x42000000, 0x42000100, 0x42080000, 0x42080100
	},
	/* S6 */
	{
		0x00000000, 0x00000010, 0x00004000, 0x00004010,
		0x00400000, 0x00400010, 0x00404000, 0x00404010,
		0x20000000, 0x20000010, 0x20004000, 0x20004010,
		0x20400000, 0x20400010, 0x20404000, 0x20404010
	},
	/* S7 */
	{
		0x00000000, 0x00000002, 0x00000800, 0x00000802,
		0x00200000, 0x00200002, 0x00200800, 0x00200802,
		0x04000000, 0x04000002, 0x04000800, 0x04000802,
		0x04200000, 0x04200002, 0x04200800, 0x04200802
	},
	/* S8 */
	{
		0x00000000, 0x00000040, 0x00001000, 0x00001040,
		0x00040000, 0x00040040, 0x00041000, 0x00041040,
		0x10000000, 0x10000040, 0x10001000, 0x10001040,
		0x10040000, 0x10040040, 0x10041000, 0x10041040
	},
};

/*
 * DES Feistel round: applies E expansion (implicit via the subkey
 * layout and right-half rotation), S-box substitution, and
 * P permutation.
 *
 * Two subkey words per round: sk[0] covers S-boxes 2,4,6,8 and
 * sk[1] (used with right-half rotated by 4) covers S-boxes 1,3,5,7.
 *
 * Uses factored sbox[] + ptab[] tables (1024 bytes total) instead
 * of the combined sp[8][64] (2048 bytes).
 */
static inline void des_round(uint32_t *l, uint32_t *r,
		const uint32_t *sk)
{
	uint32_t t, f;

	t = sk[0] ^ *r;
	f  = ptab[7][sbox[7][(t)       & 0x3F]];
	f ^= ptab[5][sbox[5][(t >>  8) & 0x3F]];
	f ^= ptab[3][sbox[3][(t >> 16) & 0x3F]];
	f ^= ptab[1][sbox[1][(t >> 24) & 0x3F]];

	t = sk[1] ^ ((*r << 28) | (*r >> 4));
	f ^= ptab[6][sbox[6][(t)       & 0x3F]];
	f ^= ptab[4][sbox[4][(t >>  8) & 0x3F]];
	f ^= ptab[2][sbox[2][(t >> 16) & 0x3F]];
	f ^= ptab[0][sbox[0][(t >> 24) & 0x3F]];

	*l ^= f;
}

#endif /* CONFIG_MBEDCRYPTO_DES_TABLE */

/*
 * FIPS 46-3 Permuted Choice 1 (PC1):
 * selects and permutes 56 key bits from the 64-bit DES key.
 * Split into C (left 28 bits) and D (right 28 bits).
 * Entries are 1-based bit positions in the 64-bit key (MSB = 1).
 */
static const uint8_t pc1_c[28] = {
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36
};

static const uint8_t pc1_d[28] = {
	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

/*
 * FIPS 46-3 Permuted Choice 2 (PC2):
 * selects 48 subkey bits from the 56-bit (C||D) state.
 * Entries are 1-based bit positions in the 56-bit value (MSB = 1).
 */
static const uint8_t pc2[48] = {
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

/*
 * Per-round left-rotation amounts for the key schedule.
 */
static const uint8_t key_rot[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

/*
 * Bit-swap helper: swap bits between two halves using a mask and
 * shift distance. This is the "delta swap" technique, a standard
 * approach for implementing bit permutations efficiently.
 */
static inline void bit_swap(uint32_t *a, uint32_t *b,
		uint32_t mask, int shift)
{
	uint32_t t = ((*a >> shift) ^ *b) & mask;

	*b ^= t;
	*a ^= (t << shift);
}

/*
 * DES Initial Permutation (IP) - FIPS 46-3 Table 1.
 *
 * Decomposed into a sequence of delta-swaps followed by a rotate
 * and final odd/even separation.
 */
static inline void des_ip(uint32_t *x, uint32_t *y)
{
	uint32_t t;

	bit_swap(x, y, 0x0F0F0F0F, 4);
	bit_swap(x, y, 0x0000FFFF, 16);
	bit_swap(y, x, 0x33333333, 2);
	bit_swap(y, x, 0x00FF00FF, 8);
	*y = (*y << 1) | (*y >> 31);
	t = (*x ^ *y) & 0xAAAAAAAA;
	*y ^= t;
	*x ^= t;
	*x = (*x << 1) | (*x >> 31);
}

/*
 * DES Final Permutation (FP = IP^{-1}) - FIPS 46-3 Table 2.
 */
static inline void des_fp(uint32_t *x, uint32_t *y)
{
	uint32_t t;

	*x = (*x << 31) | (*x >> 1);
	t = (*x ^ *y) & 0xAAAAAAAA;
	*x ^= t;
	*y ^= t;
	*y = (*y << 31) | (*y >> 1);
	bit_swap(y, x, 0x00FF00FF, 8);
	bit_swap(y, x, 0x33333333, 2);
	bit_swap(x, y, 0x0000FFFF, 16);
	bit_swap(x, y, 0x0F0F0F0F, 4);
}

/*
 * Left-rotate a 28-bit value by 'n' positions.
 */
static inline uint32_t rotl28(uint32_t v, int n)
{
	return ((v << n) | (v >> (28 - n))) & 0x0FFFFFFF;
}

/*
 * Compute 16 round sub-keys from a DES key.
 *
 * Uses the standard PC1 and PC2 permutation tables. PC1 selects
 * and permutes 56 bits from the 64-bit key into two 28-bit halves
 * C and D. For each round, C and D are left-rotated, then PC2
 * selects 48 subkey bits that are packed into two 32-bit words
 * matching the round function's implicit E-expansion layout.
 */
static void des_compute_subkeys(uint32_t sk[32], const uint8_t key[8])
{
	uint64_t key64, cd56;
	uint32_t c, d, sk0, sk1;
	int i, r;

	/* Load 64-bit key (big-endian) */
	key64 = ((uint64_t)key[0] << 56) | ((uint64_t)key[1] << 48) |
		((uint64_t)key[2] << 40) | ((uint64_t)key[3] << 32) |
		((uint64_t)key[4] << 24) | ((uint64_t)key[5] << 16) |
		((uint64_t)key[6] <<  8) | (uint64_t)key[7];

	/* Apply PC1: extract 28-bit C and D halves */
	c = 0;
	d = 0;
	for (i = 0; i < 28; i++) {
		if (key64 & (1ULL << (64 - pc1_c[i])))
			c |= (1U << (27 - i));
		if (key64 & (1ULL << (64 - pc1_d[i])))
			d |= (1U << (27 - i));
	}

	/* Generate 16 round subkeys */
	for (r = 0; r < 16; r++) {

		/* Left-rotate C and D */
		c = rotl28(c, key_rot[r]);
		d = rotl28(d, key_rot[r]);

		/* Combine into 56-bit value for PC2 */
		cd56 = ((uint64_t)c << 28) | (uint64_t)d;

		/*
		 * Apply PC2: select 48 bits, pack into two words.
		 *
		 * sk0: 6-bit groups for S-boxes 2,4,6,8
		 *      at byte positions 3,2,1,0 respectively.
		 * sk1: 6-bit groups for S-boxes 1,3,5,7
		 *      at byte positions 3,2,1,0 respectively.
		 */
		sk0 = 0;
		sk1 = 0;

		/* S-box 1 (PC2 bits 0-5) -> sk1 byte 3 */
		for (i = 0; i < 6; i++) {
			if (cd56 & (1ULL << (56 - pc2[i])))
				sk1 |= (1U << (29 - i));
		}
		/* S-box 2 (PC2 bits 6-11) -> sk0 byte 3 */
		for (i = 6; i < 12; i++) {
			if (cd56 & (1ULL << (56 - pc2[i])))
				sk0 |= (1U << (29 - (i - 6)));
		}
		/* S-box 3 (PC2 bits 12-17) -> sk1 byte 2 */
		for (i = 12; i < 18; i++) {
			if (cd56 & (1ULL << (56 - pc2[i])))
				sk1 |= (1U << (21 - (i - 12)));
		}
		/* S-box 4 (PC2 bits 18-23) -> sk0 byte 2 */
		for (i = 18; i < 24; i++) {
			if (cd56 & (1ULL << (56 - pc2[i])))
				sk0 |= (1U << (21 - (i - 18)));
		}
		/* S-box 5 (PC2 bits 24-29) -> sk1 byte 1 */
		for (i = 24; i < 30; i++) {
			if (cd56 & (1ULL << (56 - pc2[i])))
				sk1 |= (1U << (13 - (i - 24)));
		}
		/* S-box 6 (PC2 bits 30-35) -> sk0 byte 1 */
		for (i = 30; i < 36; i++) {
			if (cd56 & (1ULL << (56 - pc2[i])))
				sk0 |= (1U << (13 - (i - 30)));
		}
		/* S-box 7 (PC2 bits 36-41) -> sk1 byte 0 */
		for (i = 36; i < 42; i++) {
			if (cd56 & (1ULL << (56 - pc2[i])))
				sk1 |= (1U << (5 - (i - 36)));
		}
		/* S-box 8 (PC2 bits 42-47) -> sk0 byte 0 */
		for (i = 42; i < 48; i++) {
			if (cd56 & (1ULL << (56 - pc2[i])))
				sk0 |= (1U << (5 - (i - 42)));
		}

		sk[2 * r]     = sk0;
		sk[2 * r + 1] = sk1;
	}
}

#if defined(CONFIG_MBEDCRYPTO_DES_TABLE)

/*
 * Process a single 8-byte DES block (16 rounds, fully unrolled).
 */
static void des_crypt_block(const uint32_t *SK, const uint8_t in[8],
		uint8_t out[8])
{
	uint32_t x, y;

	x = mbedcrypto_get_be32(in);
	y = mbedcrypto_get_be32(in + 4);

	des_ip(&x, &y);

	DES_ROUND(x, y, SK +  0); DES_ROUND(y, x, SK +  2);
	DES_ROUND(x, y, SK +  4); DES_ROUND(y, x, SK +  6);
	DES_ROUND(x, y, SK +  8); DES_ROUND(y, x, SK + 10);
	DES_ROUND(x, y, SK + 12); DES_ROUND(y, x, SK + 14);
	DES_ROUND(x, y, SK + 16); DES_ROUND(y, x, SK + 18);
	DES_ROUND(x, y, SK + 20); DES_ROUND(y, x, SK + 22);
	DES_ROUND(x, y, SK + 24); DES_ROUND(y, x, SK + 26);
	DES_ROUND(x, y, SK + 28); DES_ROUND(y, x, SK + 30);

	des_fp(&y, &x);

	mbedcrypto_put_be32(out, y);
	mbedcrypto_put_be32(out + 4, x);
}

/*
 * Process a single 8-byte Triple-DES block (EDE, fully unrolled).
 */
static void des3_crypt_block(const uint32_t *SK, const uint8_t in[8],
		uint8_t out[8])
{
	uint32_t x, y;

	x = mbedcrypto_get_be32(in);
	y = mbedcrypto_get_be32(in + 4);

	des_ip(&x, &y);

	/* Encrypt with K1 */
	DES_ROUND(x, y, SK +  0); DES_ROUND(y, x, SK +  2);
	DES_ROUND(x, y, SK +  4); DES_ROUND(y, x, SK +  6);
	DES_ROUND(x, y, SK +  8); DES_ROUND(y, x, SK + 10);
	DES_ROUND(x, y, SK + 12); DES_ROUND(y, x, SK + 14);
	DES_ROUND(x, y, SK + 16); DES_ROUND(y, x, SK + 18);
	DES_ROUND(x, y, SK + 20); DES_ROUND(y, x, SK + 22);
	DES_ROUND(x, y, SK + 24); DES_ROUND(y, x, SK + 26);
	DES_ROUND(x, y, SK + 28); DES_ROUND(y, x, SK + 30);

	/* Decrypt with K2 */
	DES_ROUND(y, x, SK + 32); DES_ROUND(x, y, SK + 34);
	DES_ROUND(y, x, SK + 36); DES_ROUND(x, y, SK + 38);
	DES_ROUND(y, x, SK + 40); DES_ROUND(x, y, SK + 42);
	DES_ROUND(y, x, SK + 44); DES_ROUND(x, y, SK + 46);
	DES_ROUND(y, x, SK + 48); DES_ROUND(x, y, SK + 50);
	DES_ROUND(y, x, SK + 52); DES_ROUND(x, y, SK + 54);
	DES_ROUND(y, x, SK + 56); DES_ROUND(x, y, SK + 58);
	DES_ROUND(y, x, SK + 60); DES_ROUND(x, y, SK + 62);

	/* Encrypt with K3 */
	DES_ROUND(x, y, SK + 64); DES_ROUND(y, x, SK + 66);
	DES_ROUND(x, y, SK + 68); DES_ROUND(y, x, SK + 70);
	DES_ROUND(x, y, SK + 72); DES_ROUND(y, x, SK + 74);
	DES_ROUND(x, y, SK + 76); DES_ROUND(y, x, SK + 78);
	DES_ROUND(x, y, SK + 80); DES_ROUND(y, x, SK + 82);
	DES_ROUND(x, y, SK + 84); DES_ROUND(y, x, SK + 86);
	DES_ROUND(x, y, SK + 88); DES_ROUND(y, x, SK + 90);
	DES_ROUND(x, y, SK + 92); DES_ROUND(y, x, SK + 94);

	des_fp(&y, &x);

	mbedcrypto_put_be32(out, y);
	mbedcrypto_put_be32(out + 4, x);
}

#else /* !CONFIG_MBEDCRYPTO_DES_TABLE */

/*
 * Process a single 8-byte DES block (16 Feistel rounds).
 */
static void des_crypt_block(const uint32_t *SK, const uint8_t in[8],
		uint8_t out[8])
{
	uint32_t x, y;
	const uint32_t *sk = SK;
	int i;

	x = mbedcrypto_get_be32(in);
	y = mbedcrypto_get_be32(in + 4);

	des_ip(&x, &y);

	for (i = 0; i < 8; i++) {
		des_round(&x, &y, sk);
		sk += 2;
		des_round(&y, &x, sk);
		sk += 2;
	}

	des_fp(&y, &x);

	mbedcrypto_put_be32(out, y);
	mbedcrypto_put_be32(out + 4, x);
}

/*
 * Process a single 8-byte Triple-DES block (EDE: 3 x 16 rounds).
 */
static void des3_crypt_block(const uint32_t *SK, const uint8_t in[8],
		uint8_t out[8])
{
	uint32_t x, y;
	const uint32_t *sk = SK;
	int i;

	x = mbedcrypto_get_be32(in);
	y = mbedcrypto_get_be32(in + 4);

	des_ip(&x, &y);

	/* Encrypt with K1 */
	for (i = 0; i < 8; i++) {
		des_round(&x, &y, sk);
		sk += 2;
		des_round(&y, &x, sk);
		sk += 2;
	}

	/* Decrypt with K2 */
	for (i = 0; i < 8; i++) {
		des_round(&y, &x, sk);
		sk += 2;
		des_round(&x, &y, sk);
		sk += 2;
	}

	/* Encrypt with K3 */
	for (i = 0; i < 8; i++) {
		des_round(&x, &y, sk);
		sk += 2;
		des_round(&y, &x, sk);
		sk += 2;
	}

	des_fp(&y, &x);

	mbedcrypto_put_be32(out, y);
	mbedcrypto_put_be32(out + 4, x);
}

#endif /* CONFIG_MBEDCRYPTO_DES_TABLE */

/* ------------------------------------------------------------------ */
/*  Single-DES API                                                    */
/* ------------------------------------------------------------------ */

void mbedcrypto_des_init(struct mbedcrypto_des_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

void mbedcrypto_des_cleanup(struct mbedcrypto_des_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_des_setkey(struct mbedcrypto_des_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_DES_KEYSIZE], int dir)
{
	uint32_t t;
	int i;

	if (!ctx || !key)
		return -EINVAL;

	des_compute_subkeys(ctx->sk, key);
	ctx->dir = dir;

	/* For decryption, reverse the sub-key pairs */
	if (dir == MBEDCRYPTO_DES_DECRYPT) {
		for (i = 0; i < 16; i += 2) {
			t = ctx->sk[i];
			ctx->sk[i] = ctx->sk[30 - i];
			ctx->sk[30 - i] = t;

			t = ctx->sk[i + 1];
			ctx->sk[i + 1] = ctx->sk[31 - i];
			ctx->sk[31 - i] = t;
		}
	}

	return 0;
}

int mbedcrypto_des_ecb_crypt(const struct mbedcrypto_des_ctx *ctx,
		const uint8_t in[MBEDCRYPTO_DES_BLKSIZE],
		uint8_t out[MBEDCRYPTO_DES_BLKSIZE])
{
	if (!ctx || !in || !out)
		return -EINVAL;

	des_crypt_block(ctx->sk, in, out);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Triple-DES API                                                    */
/* ------------------------------------------------------------------ */

void mbedcrypto_des3_init(struct mbedcrypto_des3_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

void mbedcrypto_des3_cleanup(struct mbedcrypto_des3_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_des3_setkey(struct mbedcrypto_des3_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_DES_KEYSIZE * 3], int dir)
{
	uint32_t tmp[32];
	int i;

	if (!ctx || !key)
		return -EINVAL;

	ctx->dir = dir;

	if (dir == MBEDCRYPTO_DES_ENCRYPT) {
		/* Encrypt (E-D-E): K1 fwd, K2 rev, K3 fwd */
		des_compute_subkeys(ctx->sk, key);
		des_compute_subkeys(tmp, key + 8);
		for (i = 0; i < 32; i += 2) {
			ctx->sk[i + 32] = tmp[30 - i];
			ctx->sk[i + 33] = tmp[31 - i];
		}
		des_compute_subkeys(ctx->sk + 64, key + 16);
	} else {
		/* Decrypt (D-E-D): K3 rev, K2 fwd, K1 rev */
		des_compute_subkeys(tmp, key + 16);
		for (i = 0; i < 32; i += 2) {
			ctx->sk[i]     = tmp[30 - i];
			ctx->sk[i + 1] = tmp[31 - i];
		}
		des_compute_subkeys(ctx->sk + 32, key + 8);
		des_compute_subkeys(tmp, key);
		for (i = 0; i < 32; i += 2) {
			ctx->sk[i + 64] = tmp[30 - i];
			ctx->sk[i + 65] = tmp[31 - i];
		}
	}

	memset(tmp, 0, sizeof(tmp));
	return 0;
}

int mbedcrypto_des3_ecb_crypt(const struct mbedcrypto_des3_ctx *ctx,
		const uint8_t in[MBEDCRYPTO_DES_BLKSIZE],
		uint8_t out[MBEDCRYPTO_DES_BLKSIZE])
{
	if (!ctx || !in || !out)
		return -EINVAL;

	des3_crypt_block(ctx->sk, in, out);

	return 0;
}
