/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * routines for ARM secondary cpus
 */

#ifndef _SECONDARY_CPU_H
#define _SECONDARY_CPU_H

/*
 * this jumper only be used for the SoC which can't flexibly
 * assign the secondary CPUs' run entry to the '__memstart'
 */
extern unsigned long secondary_trampoline[];

#endif
