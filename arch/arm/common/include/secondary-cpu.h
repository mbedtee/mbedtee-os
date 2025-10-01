/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * routines for ARM secondary cpus
 */

#ifndef _SECONDARY_CPU_H
#define _SECONDARY_CPU_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * this jumper only be used for the SoC which can't flexibly
 * assign the secondary CPUs' run entry to the '__memstart'
 */
extern unsigned long secondary_trampoline[];

#ifdef __cplusplus
}
#endif

#endif
