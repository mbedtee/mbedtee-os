/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel thread implementation
 */

#ifndef _KTHREAD_H
#define _KTHREAD_H

#include <thread.h>

/*
 * Create a kernel thread on current CPU
 * @func - thread function to run.
 * @data - data pointer for the func().
 * @stack_size - kernel thread's stack size.
 * @namefmt - name of this thread with printk-style.
 * (No more than 64 characters)
 *
 * return the thread ID
 */
int __kthread_create(thread_func_t func, void *data,
	    size_t stack_size, const char *namefmt, ...);

/*
 * Create a kernel thread on current CPU
 * @func - thread function to run.
 * @data - data pointer for the func().
 * @namefmt - name of this thread with printk-style.
 * (No more than 64 characters)
 *
 * return the thread ID
 */
#define kthread_create(func, data, namefmt, ...)	\
({													\
	int _id_ = __kthread_create(func, data,			\
		PAGE_SIZE * (sizeof(long)/sizeof(int)),		\
		namefmt, ##__VA_ARGS__);					\
	_id_;											\
})

/*
 * Create and bind a kernel thread to a CPU
 * @func - thread function to run.
 * @data - data pointer for the func().
 * @cpu - the cpu on which the thread should be bound.
 * @namefmt - name of this thread with printk-style.
 * (No more than 64 characters)
 */
#define kthread_create_on(func, data, cpu, namefmt, ...)	\
({															\
	int _id_ = kthread_create(func, data,					\
		namefmt, ##__VA_ARGS__);							\
	sched_bind(_id_, cpu);									\
	_id_;													\
})

/*
 * Create and run a kernel thread on a most idle CPU
 * @func - thread function to run.
 * @data - data pointer for the func().
 * @namefmt - name of this thread with printk-style.
 * (No more than 64 characters)
 */
#define kthread_run(func, data, namefmt, ...)	\
({												\
	int _id_ = kthread_create(func, data,		\
	    namefmt, ##__VA_ARGS__);				\
	sched_ready(_id_);							\
	_id_;										\
})

/*
 * Create and run a kernel thread on the given CPU
 * @func - thread function to run.
 * @data - data pointer for the func().
 * @cpu - the cpu on which the thread should be bound.
 * @namefmt - name of this thread with printk-style.
 * (No more than 64 characters)
 */
#define kthread_run_on(func, data, cpu, namefmt, ...)	\
({														\
	int _id_ = kthread_create_on(func, data,			\
		cpu, namefmt, ##__VA_ARGS__);					\
	sched_ready(_id_);									\
	_id_;												\
})

#endif
