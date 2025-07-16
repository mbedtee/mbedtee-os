/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * PRNG for kernel modules
 */

#ifndef _PRNG_H
#define _PRNG_H

#ifdef __cplusplus
extern "C" {
#endif

ssize_t prng(void *buf, size_t count);

#ifdef __cplusplus
}
#endif
#endif
