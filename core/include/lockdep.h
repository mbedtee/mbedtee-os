/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * spinlock/mutex/sema dependences
 */

#ifndef _LOCKDEP_H
#define _LOCKDEP_H

#include <generated/autoconf.h>

struct lockval {
#if defined(CONFIG_ARM)
	unsigned char val;
#else
	/*
	 * mips/riscv atomic extension doesn't
	 * support to operate on byte aligned memory
	 */
	int val;
#endif
};

#define LOCKVAL_INIT(v) ((struct lockval){(v)})

#define lock_val_init(l) ({(l)->val = 0; })

/*
 * try to acquire exclusive
 */
int arch_atomic_acquire(struct lockval *lv);

/*
 * try to acquire exclusive, no wait
 */
int arch_atomic_tryacquire(struct lockval *lv);

/*
 * release exclusive
 */
void arch_atomic_release(struct lockval *lv);

/*
 * try to decrease the sema
 */
int arch_semaphore_acquire(struct lockval *lv);

/*
 * try to increase the sema
 */
int arch_semaphore_release(struct lockval *lv, unsigned int *limit);

#endif
