/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Barrier (AArch32)
 */

#ifndef _BARRIER_H
#define _BARRIER_H

#define isb(option) ({asm volatile ("isb" #option : : : "memory", "cc"); })
#define dsb(option) ({asm volatile ("dsb " #option : : : "memory", "cc"); })
#define dmb(option) ({asm volatile ("dmb " #option : : : "memory", "cc"); })

/*
 * make sure any earlier memory related instructions to be
 * finished on all CPUs before any later memory related instructions
 */
#define mb()		dsb()

/*
 * make sure any earlier memory related instructions to be
 * finished on all CPUs before any later memory related instructions
 */
#define rmb()		dsb()

/*
 * make sure any earlier memory stores to be
 * finished on all CPUs before any later memory stores
 */
#define wmb()		dsb(st)

/*
 * make sure any earlier memory related instructions to be finished
 * on inner shareable CPUs before any later memory related instructions
 */
#define smp_mb()	dsb(ish) /* memory barrier - inner shareable domain */

/*
 * make sure any earlier memory related instructions to be finished
 * on inner shareable CPUs before any later memory related instructions
 */
#define smp_rmb()	dsb(ish) /* memory barrier - inner shareable domain */

/*
 * make sure any earlier memory stores to be finished
 * on inner shareable CPUs before any later memory stores
 */
#define smp_wmb()	dsb(ishst) /* STORE memory barrier - inner shareable domain */

#endif
