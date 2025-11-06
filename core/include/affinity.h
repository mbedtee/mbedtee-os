/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * cpu affinity struct
 */

#ifndef _AFFINITY_H
#define _AFFINITY_H

#include <bitops.h>

struct cpu_affinity {
	DECLARE_BITMAP(cpus, CONFIG_NR_CPUS);
};

extern struct cpu_affinity cpus_online[1];
extern struct cpu_affinity cpus_error[1];
extern struct cpu_affinity cpus_possible[1];

/*
 * Set the bit@idx in a cpu_affinity struct
 */
static inline void cpu_affinity_set(struct cpu_affinity *affinity, unsigned int idx)
{
	bitmap_set_bit(affinity->cpus, idx);
}

/*
 * Clear the bit@idx in a cpu_affinity struct
 */
static inline void cpu_affinity_clear(struct cpu_affinity *affinity, unsigned int idx)
{
	bitmap_clear_bit(affinity->cpus, idx);
}

static inline bool cpu_affinity_isset(const struct cpu_affinity *affinity, unsigned int idx)
{
	return bitmap_bit_isset(affinity->cpus, idx);
}

/*
 * Find the next set bit in a cpu_affinity struct
 * the struct has max 'CONFIG_NR_CPUS' bits, #start indicates the offset.
 * #start should be always smaller than #nbits.
 *
 * return #start ~ #nbits - 1 normally (start <= ret < nbits)
 * return #nbits if the input bits between start/nbits are all zero.
 */
static inline unsigned int cpu_affinity_next_one(
	const struct cpu_affinity *affinity, unsigned int start)
{
	return bitmap_next_one(affinity->cpus, CONFIG_NR_CPUS, start);
}

/*
 * Find the next zero bit in a cpu_affinity struct
 * the struct has max 'CONFIG_NR_CPUS' bits, #start indicates the offset.
 * #start should be always smaller than #nbits.
 *
 * return #start ~ #nbits - 1 normally (start <= ret < nbits)
 * return #nbits if the input bits between start/nbits are all set.
 */
static inline unsigned int cpu_affinity_next_zero(
	const struct cpu_affinity *affinity, unsigned int start)
{
	return bitmap_next_zero(affinity->cpus, CONFIG_NR_CPUS, start);
}

/*
 * return the max. number of possible CPUs
 */
static inline unsigned int cpu_max_possible_num(void)
{
	return bitmap_fls(cpus_possible->cpus, BITMAP_LONG(CONFIG_NR_CPUS)) + 1;
}

static inline void cpu_affinity_and(
	struct cpu_affinity *dst, const struct cpu_affinity *a1,
	const struct cpu_affinity *a2)
{
	bitmap_and(dst->cpus, a1->cpus, a2->cpus, cpu_max_possible_num());
}

static inline void cpu_affinity_or(
	struct cpu_affinity *dst, const struct cpu_affinity *a1,
	const struct cpu_affinity *a2)
{
	bitmap_or(dst->cpus, a1->cpus, a2->cpus, cpu_max_possible_num());
}

static inline void cpu_affinity_copy(
	struct cpu_affinity *dst, const struct cpu_affinity *src)
{
	bitmap_copy(dst->cpus, src->cpus, cpu_max_possible_num());
}

static inline void cpu_affinity_zero(struct cpu_affinity *dst)
{
	bitmap_zero(dst->cpus, CONFIG_NR_CPUS);
}

static inline void cpu_affinity_fill(struct cpu_affinity *dst)
{
	cpu_affinity_copy(dst, cpus_possible);
}

#define VALID_CPUID(cpu)		((unsigned int)(cpu) < cpu_max_possible_num())

#define cpu_affinity_valid(cpu)	VALID_CPUID(cpu)

#define cpu_affinity_empty(affinity) \
	(!cpu_affinity_valid(cpu_affinity_next_one((affinity), 0)))

#define for_each_affinity_cpu(bit, affinity) \
	for ((bit) = 0; (bit) = cpu_affinity_next_one((affinity), (bit)), \
			cpu_affinity_valid(bit); (bit)++)

#define for_each_possible_cpu(cpu)       \
	for_each_affinity_cpu((cpu), cpus_possible)

#define for_each_online_cpu(cpu)         \
	for_each_affinity_cpu((cpu), cpus_online)

#endif
