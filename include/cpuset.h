/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * cpuset operations
 */

#ifndef _SYS_CPUSET_H_
#define _SYS_CPUSET_H_

#include <stdbool.h>
#include <string.h>

#define CPUSET_DEFAULT_CPUS (512)
#define CPUSET_MAX_CPUS (2048)

#define CPUSET_BITPERLONG (sizeof(long) * 8)

/* number of long integers needed for ncpus cpuset */
#define CPUSET_NR_LONG(ncpus) ((((ncpus) + CPUSET_BITPERLONG - 1) / CPUSET_BITPERLONG))

typedef struct {
	unsigned long cpus[CPUSET_NR_LONG(CPUSET_DEFAULT_CPUS)];
} cpu_set_t;

/*
 * Set the bit@idx in a cpu_set_t struct
 */
static inline void CPU_SET(unsigned int idx, cpu_set_t *cpuset)
{
	cpuset->cpus[idx / CPUSET_BITPERLONG] |= (1UL << (idx % CPUSET_BITPERLONG));
}

/*
 * Clear the bit@idx in a cpu_set_t struct
 */
static inline void CPU_CLR(unsigned int idx, cpu_set_t *cpuset)
{
	cpuset->cpus[idx / CPUSET_BITPERLONG] &= ~(1UL << (idx % CPUSET_BITPERLONG));
}

static inline bool CPU_ISSET(unsigned int idx, cpu_set_t *cpuset)
{
	return !!(cpuset->cpus[idx / CPUSET_BITPERLONG] & (1UL << (idx % CPUSET_BITPERLONG)));
}

static inline void CPU_AND(
	cpu_set_t *dst, const cpu_set_t *a1,
	const cpu_set_t *a2)
{
	unsigned int i, cnt = CPUSET_DEFAULT_CPUS / CPUSET_BITPERLONG;

	for (i = 0; i < cnt; i++)
		dst->cpus[i] = a1->cpus[i] & a2->cpus[i];
}

static inline void CPU_OR(
	cpu_set_t *dst, const cpu_set_t *a1,
	const cpu_set_t *a2)
{
	unsigned int i, cnt = CPUSET_DEFAULT_CPUS / CPUSET_BITPERLONG;

	for (i = 0; i < cnt; i++)
		dst->cpus[i] = a1->cpus[i] | a2->cpus[i];
}

static inline void CPU_COPY(
	cpu_set_t *dst, const cpu_set_t *src)
{
	memcpy(dst->cpus, src->cpus, sizeof(cpu_set_t));
}

static inline void CPU_ZERO(cpu_set_t *dst)
{
	memset(dst, 0, sizeof(cpu_set_t));
}

static inline void CPU_FILL(cpu_set_t *dst)
{
	memset(dst, 0xff, sizeof(cpu_set_t));
}

#endif
