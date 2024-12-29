/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * PRNG for kernel modules
 */

#ifndef _PRNG_H
#define _PRNG_H

ssize_t prng(void *buf, size_t count);

#endif
