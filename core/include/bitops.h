/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * bitops
 */

#ifndef _BITOPS_H
#define _BITOPS_H

#include <cpu.h>
#include <errno.h>
#include <string.h>

/*
 * Find the first set bit in an integer
 *
 * return {1 ~ BITS_PER_INT} normally;
 * return 0 if the input is 0.
 */
static inline int __ffs(unsigned int x)
{
	return __builtin_ffs(x);
}

/*
 * Find the first set bit in a long integer
 *
 * return {1 ~ BITS_PER_LONG} normally;
 * return 0 if the input is 0.
 */
static inline int __ffsl(unsigned long x)
{
	return __builtin_ffsl(x);
}

/*
 * Count the trailing zero bit in an integer (LSB)
 * Similar as the __ffs(), normally __ctz() = __ffs() - 1
 *
 * return {0 ~ BITS_PER_INT - 1} normally;
 * return BITS_PER_INT if the input is 0.
 */
static inline int __ctz(unsigned int x)
{
	return __builtin_ctz(x);
}

/*
 * Count the trailing zero bit in a long integer (LSB)
 * Similar as the __ffsl(), normally __ctzl() = __ffsl() - 1
 *
 * return {0 ~ BITS_PER_LONG - 1} normally;
 * return BITS_PER_LONG if the input is 0.
 */
static inline int __ctzl(unsigned long x)
{
	return __builtin_ctzl(x);
}

/*
 * Find the first zero bit in an integer
 *
 * return {0 ~ (BITS_PER_INT - 1)} normally;
 * return BITS_PER_INT if the input is -1.
 */
static inline int __ffz(unsigned int x)
{
	return __ctz(~x);
}

/*
 * Find the first zero bit in a long integer
 *
 * return {0 ~ (BITS_PER_LONG - 1)} normally;
 * return BITS_PER_LONG if the input is -1.
 */
static inline int __ffzl(unsigned long x)
{
	return __ctzl(~x);
}

/*
 * Find the last set bit in an integer
 *
 * return {0 ~ (BITS_PER_INT - 1)} normally;
 * return -1 if the input is zero.
 */
static inline int __fls(unsigned int x)
{
	return BITS_PER_INT - 1 - __builtin_clz(x);
}

/*
 * Find the last set bit in a long integer
 *
 * return {0 ~ (BITS_PER_LONG - 1)} normally;
 * return -1 if the input is zero.
 */
static inline int __flsl(unsigned long x)
{
	return BITS_PER_LONG - 1 - __builtin_clzl(x);
}

/* start from S bit, end at E bit (S <= x <= E) */
#define BITMAP_MASK(S, E) (((-1UL) << (S)) & (-1UL >> (BITS_PER_LONG - (E))))

/* number of long integers needed for nbits bitmap */
#define BITMAP_LONG(nbits) ((((nbits) + BITS_PER_LONG - 1) / BITS_PER_LONG))

/* declare a bitmap with number of bits */
#define DECLARE_BITMAP(name, nbits) unsigned long name[BITMAP_LONG(nbits)]

/*
 * Set the bit@idx in a long integer array
 */
static inline void bitmap_set_bit(unsigned long *bmap, unsigned int idx)
{
	bmap[idx >> BIT_SHIFT_PER_LONG] |= (1UL << (idx & BIT_MASK_PER_LONG));
}

/*
 * Clear the bit@idx in a long integer array
 */
static inline void bitmap_clear_bit(unsigned long *bmap, unsigned int idx)
{
	bmap[idx >> BIT_SHIFT_PER_LONG] &= ~(1UL << (idx & BIT_MASK_PER_LONG));
}

static inline bool bitmap_bit_isset(unsigned long *bmap, unsigned int idx)
{
	return !!(bmap[idx >> BIT_SHIFT_PER_LONG] & (1UL << (idx & BIT_MASK_PER_LONG)));
}

/*
 * Find the last set bit in a bitmap
 * the bitmap has 'nr' of long integers.

 * return 0 ~ (number*(32 or 64) - 1) normally;
 * return -1 if the input array are all zero.
 */
static inline int bitmap_fls(unsigned long *bmap, unsigned int nr)
{
	int i = 0;

	for (i = nr - 1; i >= 0; i--) {
		if (bmap[i] != 0)
			return __flsl(bmap[i]) + (i << BIT_SHIFT_PER_LONG);
	}

	return -1;
}

unsigned int bitmap_find_next_zero(unsigned long *bmap,
	unsigned int nbits, unsigned int start);

unsigned int bitmap_find_next_one(unsigned long *bmap,
	unsigned int nbits, unsigned int start);

/*
 * Find the next set bit in a bitmap
 * the bitmap has 'nbits', #start indicates the offset.
 * #start should be always smaller than #nbits.
 *
 * return #start ~ #nbits - 1 normally (start <= ret < nbits)
 * return #nbits if the input bits between start/nbits are all zero.
 */
static inline unsigned int bitmap_next_one(unsigned long *bmap,
	unsigned int nbits, unsigned int start)
{
	if (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG) {
		if (start >= nbits)
			return nbits;

		unsigned long val = *bmap & BITMAP_MASK(start, nbits);

		return val ? __ctzl(val) : nbits;
	}

	return bitmap_find_next_one(bmap, nbits, start);
}

/*
 * Find the next zero bit in a bitmap
 * the bitmap has 'nbits', #start indicates the offset.
 * #start should be always smaller than #nbits.
 *
 * return #start ~ #nbits - 1 normally (start <= ret < nbits)
 * return #nbits if the input bits between start/nbits are all set.
 */
static inline unsigned int bitmap_next_zero(unsigned long *bmap,
	unsigned int nbits, unsigned int start)
{
	if (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG) {
		if (start >= nbits)
			return nbits;

		unsigned long val = ~(*bmap & BITMAP_MASK(start, nbits));

		return val ? __ctzl(val) : nbits;
	}

	return bitmap_find_next_zero(bmap, nbits, start);
}

/*
 * Find the next contiguous zero area in a bitmap
 * the bitmap has 'nbits', #start indicates the offset.
 * #nr indicates the number of zero bits looking for
 *
 * return #start ~ #nbits - 1 normally (start <= ret < nbits)
 * return #nbits if no contiguous zero area found between start/nbits.
 */
static inline unsigned int bitmap_next_zero_area(
	unsigned long *bmap, unsigned int nbits,
	unsigned int start, unsigned int nr)
{
	unsigned int id = 0, end = 0;

again:
	id = bitmap_next_zero(bmap, nbits, start);

	end = id + nr;
	if (end > nbits)
		return nbits;

	start = bitmap_next_one(bmap, end, id);
	if (start < end)
		goto again;

	return id;
}

/*
 * Find the max contiguous zero area in a 'nbits' bitmap
 *
 * return the idx - #0 ~ #nbits - 1 normally (0 <= ret < nbits)
 */
static inline unsigned int bitmap_max_zero_area(
	unsigned long *bmap, unsigned int nbits, unsigned int *max)
{
	unsigned int id0 = 0, id1 = 0, maxz = 0, ret = 0;

	while (id1 < nbits) {
		id0 = bitmap_next_zero(bmap, nbits, id1);
		id1 = bitmap_next_one(bmap, nbits, id0);
		if ((id1 - id0) > maxz) {
			ret = id0;
			maxz = id1 - id0;
		}
	}

	*max = maxz;
	return ret;
}

/*
 * set #nbits to 1, start from #start bit
 * (start <= x < start + nbits)
 */
static inline void bitmap_set(unsigned long *bmap,
	unsigned int start, unsigned int nbits)
{
	if (__builtin_constant_p(start + nbits) &&
		(start + nbits >= 1 && start + nbits <= BITS_PER_LONG))
		*bmap |= BITMAP_MASK(start, start + nbits);
	else if (__builtin_constant_p(start & 7) && !(start & 7) &&
		 __builtin_constant_p(nbits & 7) && !(nbits & 7))
		memset((char *)bmap + start / 8, 0xff, nbits / 8);
	else {
		int end = start + nbits;
		int idx = start >> BIT_SHIFT_PER_LONG;
		int nrset = BITS_PER_LONG - (start & BIT_MASK_PER_LONG);
		unsigned long mask = -1UL << (start & BIT_MASK_PER_LONG);

		while ((int)(nbits - nrset) >= 0) {
			bmap[idx++] |= mask;
			nbits -= nrset;
			nrset = BITS_PER_LONG;
			mask = -1UL;
		}

		if (nbits)
			bmap[idx] |= mask & ~(-1UL << (end & BIT_MASK_PER_LONG));
	}
}

/*
 * clear #nbits to 0, start from #start bit
 * (start <= x < start + nbits)
 */
static inline void bitmap_clear(unsigned long *bmap,
	unsigned int start, unsigned int nbits)
{
	if (__builtin_constant_p(start + nbits) &&
		(start + nbits >= 1 && start + nbits <= BITS_PER_LONG))
		*bmap &= ~(BITMAP_MASK(start, start + nbits));
	else if (__builtin_constant_p(start & 7) && !(start & 7) &&
		 __builtin_constant_p(nbits & 7) && !(nbits & 7))
		memset((char *)bmap + start / 8, 0x00, nbits / 8);
	else {
		int end = start + nbits;
		int idx = start >> BIT_SHIFT_PER_LONG;
		int nrclear = BITS_PER_LONG - (start & BIT_MASK_PER_LONG);
		unsigned long mask = ~(-1UL << (start & BIT_MASK_PER_LONG));

		while ((int)(nbits - nrclear) >= 0) {
			bmap[idx++] &= mask;
			nbits -= nrclear;
			nrclear = BITS_PER_LONG;
			mask = 0;
		}

		if (nbits)
			bmap[idx] &= mask | (-1UL << (end & BIT_MASK_PER_LONG));
	}
}

static inline void bitmap_zero(unsigned long *dst, unsigned int nbits)
{
	if (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)
		*dst = 0;
	else
		memset(dst, 0, roundup(nbits, BITS_PER_LONG) >> 3);
}

static inline void bitmap_fill(unsigned long *dst, unsigned int nbits)
{
	if (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)
		*dst = BITMAP_MASK(0, nbits);
	else
		memset(dst, 0xff, roundup(nbits, BITS_PER_LONG) >> 3);
}

void __bitmap_and(unsigned long *dst, const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits);

void __bitmap_or(unsigned long *dst, const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits);

static inline void bitmap_and(unsigned long *dst, const unsigned long *bmap1,
			const unsigned long *bmap2, unsigned int nbits)
{
	if (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)
		*dst = *bmap1 & *bmap2 & BITMAP_MASK(0, nbits);
	else
		__bitmap_and(dst, bmap1, bmap2, nbits);
}

static inline void bitmap_or(unsigned long *dst, const unsigned long *bmap1,
			const unsigned long *bmap2, unsigned int nbits)
{
	if (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)
		*dst = (*bmap1 | *bmap2) & BITMAP_MASK(0, nbits);
	else
		__bitmap_or(dst, bmap1, bmap2, nbits);
}

static inline void bitmap_copy(unsigned long *dst, const unsigned long *src,
			unsigned int nbits)
{
	if (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)
		*dst = *src;
	else
		memcpy(dst, src, roundup(nbits, BITS_PER_LONG) >> 3);
}

#define for_each_set_bit(bit, bmap, nbits) \
	for ((bit) = 0; (bit) = bitmap_next_one((bmap), (nbits), (bit)), \
			(bit) < (nbits); (bit)++)

#endif
