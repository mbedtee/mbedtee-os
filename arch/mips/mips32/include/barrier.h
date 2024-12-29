/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Barrier (MIPS32)
 */

#ifndef _BARRIER_H
#define _BARRIER_H

/* memory barrier */
#define mb(option) ({asm volatile ("sync " #option : : : "memory", "cc"); })

#define rmb()		mb() /* memory barrier */
#define wmb()		mb() /* memory barrier */

/*
 * make sure any earlier memory related instructions to
 * be finished before any later memory related instructions
 */
#define smp_mb()	mb()

/*
 * make sure any earlier memory loads to
 * be finished before any later memory loads
 */
#define smp_rmb()	rmb()

/*
 * drain the write buffer
 * make sure any earlier memory stores to
 * be finished before any later memory stores
 */
#define smp_wmb()	wmb()

#endif
