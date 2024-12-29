/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RNG framework
 */

#ifndef _RNG_H
#define _RNG_H

#include <stddef.h>
#include <generated/autoconf.h>

struct rng_struct {
	const char *name;
	void (*suspend)(const struct rng_struct *p);
	void (*resume)(const struct rng_struct *p);
	ssize_t (*read)(const struct rng_struct *p, void *buf, size_t cnt);
	void *priv;
};

void rng_register(const struct rng_struct *r);

#endif
