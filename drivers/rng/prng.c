// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Pseudo RNG
 */

#include <io.h>
#include <of.h>
#include <rng.h>
#include <prng.h>
#include <sched.h>
#include <trace.h>
#include <driver.h>
#include <timer.h>
#include <thread.h>

static uint64_t _seed;

int rand(void)
{
	const uint64_t salt = 0x7B4C7A4F5B2AE62D;

	_seed = _seed * (salt + (uintptr_t)current);

	return (_seed >> 32) & RAND_MAX;
}

ssize_t prng(void *buf, size_t count)
{
	size_t n = 0, ops = 0;
	const uint64_t salt = 0x7B4C7A4F5B2AE62D;
	uint64_t seed = 0;
	unsigned long flags = 0;

	local_irq_save(flags);

	seed = _seed + (read_cycles() + (percpu_id() << 16));

	while (n < count) {
		seed = seed * (salt + (uintptr_t)current);
		ops = min(count - n, sizeof(seed));
		memcpy(buf + n, &seed, ops);
		n += ops;
	}

	_seed = seed;

	local_irq_restore(flags);

	return n;
}

static ssize_t prng_read(const struct rng_struct *p,
	void *buf, size_t count)
{
	return prng(buf, count);
}

static void prng_suspend(const struct rng_struct *p)
{
}

static void prng_resume(const struct rng_struct *p)
{
}

static const struct rng_struct prng_struct = {
	.name = "PRNG",
	.read = prng_read,
	.suspend = prng_suspend,
	.resume = prng_resume,
};

static void __init prng_init(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	_seed = ((uint64_t)ts.tv_nsec << BITS_PER_INT) + ts.tv_sec;
	_seed -= (uintptr_t)&_seed;

	rng_register(&prng_struct);
}

EARLY_INIT(prng_init);
