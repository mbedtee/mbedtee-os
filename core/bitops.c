// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * bitops
 */

#include <errno.h>
#include <bitops.h>

/*
 * Find the next zero bit in a bitmap
 * the bitmap has 'nbits', #start indicates the offset.
 * #start should be always smaller than #nbits.
 *
 * return #start ~ #nbits - 1 normally (start <= ret < nbits)
 * return #nbits if the input bits between start/nbits are all set.
 */
unsigned int bitmap_find_next_zero(const unsigned long *bmap,
	unsigned int nbits, unsigned int start)
{
	unsigned int bid = 0;
	unsigned long val = 0;
	unsigned long s_unalign = 0;

	if (start >= nbits)
		return nbits;

	s_unalign = -1UL << (start & BIT_MASK_PER_LONG);

	for (bid = (start >> BIT_SHIFT_PER_LONG),
		val = ~(bmap[bid]) & s_unalign; val == 0;
		val = ~(bmap[bid])) {
		if (((bid + 1) << BIT_SHIFT_PER_LONG) >= nbits)
			return nbits;
		bid++;
	}

	return min(__ctzl(val) + (bid << BIT_SHIFT_PER_LONG), nbits);
}

/*
 * Find the next set bit in a bitmap
 * the bitmap has 'nbits', #start indicates the offset.
 * #start should be always smaller than #nbits.
 *
 * return #start ~ #nbits - 1 normally (start <= ret < nbits)
 * return #nbits if the input bits between start/nbits are all zero.
 */
unsigned int bitmap_find_next_one(const unsigned long *bmap,
	unsigned int nbits, unsigned int start)
{
	unsigned int bid = 0;
	unsigned long val = 0;
	unsigned long s_unalign = 0;

	if (start >= nbits)
		return nbits;

	s_unalign = -1UL << (start & BIT_MASK_PER_LONG);

	for (bid = (start >> BIT_SHIFT_PER_LONG),
		val = (bmap[bid] & s_unalign); val == 0;
		val = bmap[bid]) {
		if (((bid + 1) << BIT_SHIFT_PER_LONG) >= nbits)
			return nbits;
		bid++;
	}

	return min(__ctzl(val) + (bid << BIT_SHIFT_PER_LONG), nbits);
}

void __bitmap_and(unsigned long *dst, const unsigned long *bmap1,
			const unsigned long *bmap2, unsigned int nbits)
{
	unsigned int i, cnt = nbits >> BIT_SHIFT_PER_LONG;
	unsigned int residue = nbits & BIT_MASK_PER_LONG;

	for (i = 0; i < cnt; i++)
		dst[i] = bmap1[i] & bmap2[i];

	if (residue)
		dst[i] = bmap1[i] & bmap2[i] & BITMAP_MASK(0, residue);
}

void __bitmap_or(unsigned long *dst, const unsigned long *bmap1,
			const unsigned long *bmap2, unsigned int nbits)
{
	unsigned int i, cnt = nbits >> BIT_SHIFT_PER_LONG;
	unsigned int residue = nbits & BIT_MASK_PER_LONG;

	for (i = 0; i < cnt; i++)
		dst[i] = bmap1[i] | bmap2[i];

	if (residue)
		dst[i] = (bmap1[i] | bmap2[i]) & BITMAP_MASK(0, residue);
}
