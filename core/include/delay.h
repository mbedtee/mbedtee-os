/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * mdelay() and udelay()
 */

#ifndef _DELAY_H
#define _DELAY_H

#ifdef __cplusplus
extern "C" {
#endif

void udelay(unsigned long usecs);
void mdelay(unsigned long msecs);

#ifdef __cplusplus
}
#endif
#endif
