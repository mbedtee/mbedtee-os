/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Barrier (RISCV)
 */

#ifndef _BARRIER_H
#define _BARRIER_H

#define fence(pred, succ) ({asm volatile("fence " #pred "," #succ : : : "memory", "cc"); })

/*
 * make sure any earlier io/memory related instructions to
 * be finished before any later io/memory related instructions
 */
#define mb()		fence(iorw, iorw)

/*
 * make sure any earlier io/memory loads to
 * be finished before any later io/memory loads
 */
#define rmb()		fence(ir, ir)

/*
 * make sure any earlier io/memory stores to
 * be finished before any later io/memory stores
 */
#define wmb()		fence(ow, ow)

/*
 * make sure any earlier memory related instructions to
 * be finished before any later memory related instructions
 */
#define smp_mb()	fence(rw, rw)

/*
 * make sure any earlier memory loads to
 * be finished before any later memory loads
 */
#define smp_rmb()	fence(r, r)

/*
 * make sure any earlier memory stores to
 * be finished before any later memory stores
 */
#define smp_wmb()	fence(w, w)

#define isb() ({asm volatile ("fence.i" : : : "memory", "cc"); })

#endif
