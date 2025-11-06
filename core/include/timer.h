/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Define the low level timers founctions
 *
 * No matter which timer is in use, the implementation
 * should have these functions for the basal OS functionalities
 */

#ifndef _TIMER_H
#define _TIMER_H

#include <init.h>
#include <list.h>
#include <time.h>
#include <stdbool.h>
#include <sys/time.h>

struct arch_timer {
	uint64_t (*read_cycles)(void);

	void (*trigger_next)(uint64_t cycles);

	void (*enable)(struct arch_timer *t);
	void (*disable)(struct arch_timer *t);

	void *base;

	struct device_node *dn;

	struct list_head node;

	bool is_global; /* opposite: is percpu */
	unsigned int frq;

	unsigned int irq;

	unsigned int cycles_per_msecs;
	unsigned int cycles_per_usecs;

	/*
	 * amplify to 1KK (1048576) times
	 * to enhance the precision
	 */
	unsigned int nsecs_per_cycles;
	unsigned int cycles_per_nsecs;
	unsigned int usecs_per_cycles;
};

#define DECLARE_TIMER(name, compatible, initfn)                 \
	static const struct of_compat_init __of_timer_##name        \
	  __of_timerinit = {.compat = (compatible), .init = (initfn)}

extern struct arch_timer *ticktimer;

#define NANOSECS_PER_SEC (1000000000UL)
#define MICROSECS_PER_SEC (1000000UL)

#define INVALID_TIMESPEC(ts) (((ts)->tv_sec < 0) || \
		((unsigned long)(ts)->tv_nsec >= NANOSECS_PER_SEC))

#define TIMER_FRQ (ticktimer->frq)
#define CYCLES_PER_MSECS (ticktimer->cycles_per_msecs)
#define CYCLES_PER_USECS (ticktimer->cycles_per_usecs)
#define CYCLES_PER_1KKNSECS (ticktimer->cycles_per_nsecs)
#define NSECS_PER_1KKCYCLES (ticktimer->nsecs_per_cycles)
#define USECS_PER_1KKCYCLES (ticktimer->usecs_per_cycles)

/*
 * To enhance the precision, reduce error.
 * amplify the constants with a golden number.
 */
static inline uint64_t cycles_to_nsecs(uint64_t cycles)
{
	/* 1. amplify to NSECS_PER_1KKCYCLES */
	/* 2. div 1KK to match nsecs_per_cycle */
	return (cycles * NSECS_PER_1KKCYCLES) >> 20;
}

static inline uint64_t nsecs_to_cycles(uint64_t nsecs)
{
	/* 1. amplify to CYCLES_PER_1KKNSECS */
	/* 2. div 1KK to match nsecs */
	return (nsecs * CYCLES_PER_1KKNSECS) >> 20;
}

static inline uint64_t cycles_to_usecs(uint64_t cycles)
{
	/* 1. amplify to USECS_PER_1KKCYCLES */
	/* 2. div 1KK to match usecs_per_cycle */
	return (cycles * USECS_PER_1KKCYCLES) >> 20;
}

static inline uint64_t msecs_to_cycles(uint64_t msecs)
{
	return msecs * CYCLES_PER_MSECS;
}

static inline uint64_t usecs_to_cycles(uint64_t usecs)
{
	return usecs * CYCLES_PER_USECS;
}

static inline uint64_t secs_to_cycles(uint64_t secs)
{
	return secs * TIMER_FRQ;
}

static inline void cycles_to_time(uint64_t cycles,
	struct timespec *time)
{
	uint64_t nsecs = 0;

	nsecs = cycles_to_nsecs(cycles);

	/* Find number of seconds */
	if (nsecs < NANOSECS_PER_SEC) {
		time->tv_sec = 0;
		time->tv_nsec = nsecs;
	} else {
		time->tv_sec = nsecs / NANOSECS_PER_SEC;
		time->tv_nsec = nsecs - (time->tv_sec * NANOSECS_PER_SEC);
	}
}

static inline uint64_t time_to_cycles(struct timespec *time)
{
	uint64_t tmp = nsecs_to_cycles(time->tv_nsec);

	if (time->tv_sec)
		tmp += secs_to_cycles(time->tv_sec);

	return tmp;
}

static inline void usecs_to_time(uint64_t usecs,
	struct timespec *time)
{
	if (usecs < MICROSECS_PER_SEC) {
		time->tv_sec = 0;
		time->tv_nsec = usecs * 1000;
	} else {
		time->tv_sec = usecs / MICROSECS_PER_SEC;
		time->tv_nsec = (usecs - (time->tv_sec * MICROSECS_PER_SEC)) * 1000;
	}
}

static inline uint64_t time_to_usecs(const struct timespec *time)
{
	uint64_t usecs = 0;

	usecs = time->tv_nsec / 1000;
	usecs += time->tv_sec * MICROSECS_PER_SEC;

	return usecs;
}

/*
 * add 2 cycles, c1 + c2, get the abs_cycles
 */
static inline uint64_t add_cycles(uint64_t c1, uint64_t c2)
{
	return c1 + c2;
}

/*
 * substract 2 cyclestamps, c1 - c2, get the abs_cycles
 */
static inline uint64_t sub_cycles(uint64_t c1, uint64_t c2)
{
	return c1 - c2;
}

/*
 * set the tick timer to system
 */
static inline void set_ticktimer(struct arch_timer *t)
{
	ticktimer = t;
}

/*
 * read the cycles of the tick timer
 */
static inline uint64_t read_cycles(void)
{
	return ticktimer->read_cycles();
}

/*
 * set the next expire cycles of the tick timer
 */
static inline void trigger_next(uint64_t cycles)
{
	ticktimer->trigger_next(cycles);
}

/*
 * read the monotonic ticktimer's time from system start
 */
void read_time(struct timespec *val);

/*
 * parse the DTS, init the timer callbacks
 */
void timer_early_init(void);

/*
 * init/enable the ticktimer or other timers
 */
void timer_init(void);

/*
 * For CPU Hot-Plug (percpu)
 * Force turn off the percpu ticktimer or other percpu timers
 */
void timer_down(void);

#endif
