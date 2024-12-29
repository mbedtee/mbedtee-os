/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * atomic operations
 */

#ifndef _ATOMIC_H
#define _ATOMIC_H

#include <barrier.h>

struct atomic_num {
	int val;
};

#define ATOMIC_INIT(v) ((struct atomic_num){(v)})

#define atomic_clear_zero(a) ({(a)->val = 0; })

/*
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_num
 *
 * Atomically reads the value of @v.
 */
#define atomic_read(v)											\
({																\
	BUILD_ERROR_ON(!TYPE_COMPATIBLE(v, struct atomic_num *));	\
	int __v = *(__volatile int *)(v);							\
	asm volatile("" : : : "memory");							\
	__v;														\
})

#define atomic_read_x(v)										\
({																\
	typeof(*(v)) __v = *(__volatile typeof(__v) *)(v);			\
	asm volatile("" : : : "memory");							\
	__v;														\
})

/*
 * atomically sets @i to @v
 * return the old value of @v
 */
int atomic_set_return(struct atomic_num *v, int i);

/*
 * atomically sets @i to @v if old @v is equal to @expceted,
 * return true when success, return flase when @expceted!=@v and @v
 * is written into @expceted.
 */
int atomic_compare_set(struct atomic_num *v, int *expected, int i);

/*
 * atomically sets the value of @v to @i.
 */
static inline void atomic_set(struct atomic_num *v, int i)
{
	atomic_set_return(v, i);
}

/*
 * atomically adds @i to @v
 * return the new value of @v
 */
int atomic_add_return(struct atomic_num *v, int i);

/*
 * atomically subs @i to @v
 * return the new value of @v
 */
int atomic_sub_return(struct atomic_num *v, int i);


/*
 * atomically adds @i to @v
 */
static inline void atomic_add(struct atomic_num *v, int i)
{
	atomic_add_return(v, i);
}

/*
 * atomically subs @i to @v
 */
static inline void atomic_sub(struct atomic_num *v, int i)
{
	atomic_sub_return(v, i);
}

/*
 * atomically inc the @v with 1
 */
static inline void atomic_inc(struct atomic_num *v)
{
	atomic_add_return(v, 1);
}

/*
 * atomically inc the @v with 1
 * return the new value of @v
 */
static inline int atomic_inc_return(struct atomic_num *v)
{
	return atomic_add_return(v, 1);
}

/*
 * atomically dec the @v with 1
 */
static inline void atomic_dec(struct atomic_num *v)
{
	atomic_sub_return(v, 1);
}

/*
 * atomically dec the @v with 1
 * return the new value of @v
 */
static inline int atomic_dec_return(struct atomic_num *v)
{
	return atomic_sub_return(v, 1);
}

/*
 * atomic_orr - atomically orr the @v with @i
 */
void atomic_orr(struct atomic_num *v, int i);

/*
 * atomic_bic - atomically bic the @v with @i
 */
void atomic_bic(struct atomic_num *v, int i);

#endif
