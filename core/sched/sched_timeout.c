// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * sched_timeout mechanism
 */

#include <tevent.h>
#include <trace.h>
#include <sched.h>
#include <thread.h>
#include <interrupt.h>

#include "sched_list.h"
#include "sched_timer.h"

/*
 * This function wakes up the thread
 * which has called sched_timeout()
 */
void sched_timeout_event(struct tevent *t)
{
	sched_ready((intptr_t)t->data);
}

/*
 * This calling thread sleeps for given timespec
 *
 * Returns via #time
 * time.tv_sec may be negative if the timeout elapsed
 */
void sched_timespec(struct timespec *time)
{
	struct timespec curr = {0};
	unsigned long flags = 0;
	struct sched *s = NULL;

	if (time->tv_sec || time->tv_nsec) {
		local_irq_save(flags);

		s = current->sched;

		assert(in_interrupt() == false);

		sched_timed_dequeue(s, SCHED_SLEEPING, time);
		thread_schedule(current, true);

		local_irq_restore(flags);

		read_time(&curr);

		timespecsub(&s->tevent.expire, &curr, time);
	}
}

/*
 * This calling thread sleeps for
 * given number of milliseconds
 *
 * Returns:
 * 0 if the timeout(msecs) elapsed,
 * remaining msecs if the caller has been
 * waked up before timeout elapsed.
 */
uint64_t sched_msecs(uint64_t msecs)
{
	struct timespec time;
	uint64_t remain = 0;

	if (msecs == 0)
		return 0;

	usecs_to_time(msecs * 1000ULL, &time);

	sched_timespec(&time);

	if (time.tv_sec >= 0)
		remain = time_to_usecs(&time) / 1000ULL;

	return remain <= msecs ? remain : msecs;
}

/*
 * This calling thread sleeps for
 * given number of microseconds
 *
 * Returns:
 * 0 if the timeout(microseconds) elapsed,
 * remaining microseconds if the caller has been
 * waked up before timeout elapsed.
 */
uint64_t sched_usecs(uint64_t usecs)
{
	struct timespec time;
	uint64_t remain = 0;

	if (usecs == 0)
		return 0;

	usecs_to_time(usecs, &time);

	sched_timespec(&time);

	if (time.tv_sec >= 0)
		remain = time_to_usecs(&time);

	return remain <= usecs ? remain : usecs;
}

/*
 * This function starts the timeout timer,
 * and sets the thread state to waiting.
 *
 * spinlock is held before dequeue finish to avoid race-condition
 *
 * Returns via #time
 * time.tv_sec may be negative if the timeout elapsed
 */
void sched_timespec_locked(struct spinlock *slock,
	struct timespec *time, int interruptible)
{
	struct timespec curr = {0};
	struct sched *s = NULL;

	if (!time->tv_sec && !time->tv_nsec)
		return;

	assert(in_interrupt() == false);

	s = current->sched;
	sched_timed_dequeue(s, SCHED_WAITING, time);
	spin_unlock(slock);
	thread_schedule(current, interruptible);
	spin_lock(slock);
	read_time(&curr);

	timespecsub(&s->tevent.expire, &curr, time);
}

/*
 * This calling thread waits for given number of microseconds.
 *
 * spinlock is held before dequeue finish to avoid race-condition
 *
 * Returns:
 * 0 if the timeout(microseconds) elapsed,
 * remaining microseconds if the caller has been
 * waked up before timeout elapsed.
 */
uint64_t sched_timeout_locked(struct spinlock *slock,
	uint64_t usecs, int interruptible)
{
	struct timespec time;
	uint64_t remain = 0;

	if (usecs == 0)
		return 0;

	usecs_to_time(usecs, &time);

	sched_timespec_locked(slock, &time, interruptible);

	if (time.tv_sec >= 0)
		remain = time_to_usecs(&time);

	return remain <= usecs ? remain : usecs;
}

/*
 * This function starts the timeout timer,
 * and sets the thread state to waiting.
 *
 * mutexlock/spinlock are held before dequeue finish to avoid race-condition
 *
 * Returns via #time
 * time.tv_sec may be negative if the timeout elapsed
 */
void sched_timespec_mutex_locked(struct mutex *mlock,
	struct spinlock *slock, struct timespec *time, int interruptible)
{
	struct timespec curr = {0};
	struct sched *s = NULL;

	if (!time->tv_sec && !time->tv_nsec)
		return;

	assert(in_interrupt() == false);

	s = current->sched;
	sched_timed_dequeue(s, SCHED_WAITING, time);
	spin_unlock(slock);
	mutex_unlock(mlock);
	thread_schedule(current, interruptible);
	mutex_lock(mlock);
	spin_lock(slock);
	read_time(&curr);

	timespecsub(&s->tevent.expire, &curr, time);
}

/*
 * This calling thread waits for given number of microseconds.
 *
 * mutexlock/spinlock are held before dequeue finish to avoid race-condition
 *
 * Returns:
 * 0 if the timeout(microseconds) elapsed,
 * remaining microseconds if the caller has been
 * waked up before timeout elapsed.
 */
uint64_t sched_timeout_mutex_locked(struct mutex *mlock,
	struct spinlock *slock, uint64_t usecs, int interruptible)
{
	struct timespec time;
	uint64_t remain = 0;

	if (usecs == 0)
		return 0;

	usecs_to_time(usecs, &time);

	sched_timespec_mutex_locked(mlock, slock, &time, interruptible);

	if (time.tv_sec >= 0)
		remain = time_to_usecs(&time);

	return remain <= usecs ? remain : usecs;
}
