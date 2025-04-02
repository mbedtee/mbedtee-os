/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * handling the lists of the priorities
 */

#ifndef _SCHED_LIST_H
#define _SCHED_LIST_H

#include <trace.h>
#include <limits.h>
#include "sched_priv.h"
#include "sched_timer.h"

/*
 * time window in milliseconds for
 * counting the loading and priority
 */
#define SCHED_COUNT_PERIOD		(64UL)

/*
 * Define the weight of per priority level (in cycles)
 *
 * SCHED_OTHER policy will auto-decrease the
 * priority after the thread consumed CPU timeslice.
 * 'SCHED_CYCLES_PERLEVEL' and sched.consumed
 * desides how many levels the priority will be decreased.
 */
#define SCHED_WEIGHT_PERLEVEL	(CYCLES_PER_MSECS >> 2) /* 1ms/4 */

static inline void sched_list_add(struct sched_priv *sp,
	struct sched *s)
{
	int prio = s->prio;

	if (list_empty(&s->ready_node)) {
		list_add_tail(&s->ready_node, &sp->prio_lists[prio]);
		bitmap_set_bit(sp->prio_bitmap, prio);
	}
}

static inline void sched_list_del(struct sched_priv *sp,
	struct sched *s)
{
	int prio = s->prio;

	list_del(&s->ready_node);
	if (list_empty(&sp->prio_lists[prio]))
		bitmap_clear_bit(sp->prio_bitmap, prio);

	/* update round-robin priority ceiling */
	if ((s == sp->curr) && (s->policy != SCHED_OTHER))
		sp->rrprio = 0;
}

/*
 * Add to cpu alive/idle list
 */
static inline void sched_cpu_add(struct sched_priv *sp)
{
	unsigned long flags = 0;
	struct sched_gd *gd = sched_gd();

	spin_lock_irqsave(&gd->lock, flags);
	if (list_empty(&sp->node))
		list_add_tail(&sp->node, &gd->cpus);

	spin_lock(&gd->idle_lock);
	if ((list_empty(&sp->idle_node)) && (sp->ready_num == 0))
		list_add_tail(&sp->idle_node, &gd->idle_cpus);
	spin_unlock(&gd->idle_lock);

	spin_unlock_irqrestore(&gd->lock, flags);
}

/*
 * Delete from cpu alive/idle list
 */
static inline void sched_cpu_del(struct sched_priv *sp)
{
	unsigned long flags = 0;
	struct sched_gd *gd = sched_gd();

	spin_lock_irqsave(&gd->lock, flags);

	sp->ready_num = (typeof(sp->ready_num))-1 >> 1;
	list_del(&sp->node);

	spin_lock(&gd->idle_lock);
	list_del(&sp->idle_node);
	spin_unlock(&gd->idle_lock);

	spin_unlock_irqrestore(&gd->lock, flags);
}

/*
 * Add to percpu list
 */
static inline void __sched_sp_add(struct sched_priv *sp,
	struct sched *s)
{
	s->sp = sp;
	sp->total_num++;
	list_add_tail(&s->node, &sp->sl);
}

static inline void sched_sp_add(struct sched_priv *sp,
	struct sched *s)
{
	spin_lock(&sp->lock);
	__sched_sp_add(sp, s);
	spin_unlock(&sp->lock);
}

/*
 * Delete from percpu list
 */
static inline void __sched_sp_del(struct sched_priv *sp,
	struct sched *s)
{
	sp->total_num--;
	list_del(&s->node);
}

static inline void sched_sp_del(struct sched_priv *sp,
	struct sched *s)
{
	spin_lock(&sp->lock);
	__sched_sp_del(sp, s);
	spin_unlock(&sp->lock);
}

/*
 * Add to global list
 */
static inline void sched_add(struct sched *s)
{
	unsigned long flags = 0;
	struct sched_gd *gd = sched_gd();

	spin_lock_irqsave(&gd->lock, flags);
	sched_sp_add(sched_priv(), s);

	gd->scheds[s->id] = s;
	list_add_tail(&s->gd_node, &gd->sl);
	spin_unlock_irqrestore(&gd->lock, flags);
}

/*
 * Delete from global list
 */
static inline void __sched_del(struct sched *s)
{
	struct sched_gd *gd = sched_gd();

	gd->scheds[s->id] = NULL;
	list_del(&s->gd_node);
	__sched_sp_del(s->sp, s);
}

static inline void sched_idlecpu_dec(struct sched_priv *sp)
{
	struct sched_gd *gd = sched_gd();

	if (sp->ready_num++ == 0) {
		spin_lock(&gd->idle_lock);
		list_del(&sp->idle_node);
		spin_unlock(&gd->idle_lock);
	}
}

static inline void sched_idlecpu_inc(struct sched_priv *sp,
	struct sched_gd *gd)
{
	if (--sp->ready_num == 0) {
		spin_lock(&gd->idle_lock);
		assert(list_empty(&sp->idle_node));
		list_add_tail(&sp->idle_node, &gd->idle_cpus);
		spin_unlock(&gd->idle_lock);
	}
}

/*
 * change the current priority
 * move the sched entity to the dst prio's list tail
 */
static inline void sched_change_prio(
	struct sched_priv *sp, struct sched *s, int dst_prio)
{
	int curr_prio = s->prio;
	struct list_head *lists = sp->prio_lists;

	/* update the kernelspace current priority */
	s->prio = dst_prio;

	if (!list_empty(&s->ready_node)) {
		list_move_tail(&s->ready_node, &lists[dst_prio]);

		if (dst_prio != curr_prio) {
			bitmap_set_bit(sp->prio_bitmap, dst_prio);
			if (list_empty(&lists[curr_prio]))
				bitmap_clear_bit(sp->prio_bitmap, curr_prio);
		}
	}
}

/*
 * compensate timeslice for the SCHED_OTHER entity which
 * did not hold the CPU for a long time.
 *
 * move this sched entity to the dst prio's list tail
 */
static inline void sched_compensate_prio(
	struct sched_priv *sp, struct sched *s)
{
	int step = 0;
	int dst_prio = 0;
	int curr_prio = s->prio;

	if (s->policy != SCHED_OTHER)
		return;

	if (s->runtime > (SCHED_WEIGHT_PERLEVEL >> 2))
		return;

	step = max(s->priority >> 3, 1);
	if (list_empty(&s->ready_node)) {
		s->prio = min(curr_prio + step, (int)s->priority);
		return;
	}

	dst_prio = curr_prio + step;

	if (sp->rrprio)
		dst_prio = min(dst_prio, (int)sp->rrprio);
	else
		dst_prio = min(dst_prio, (int)s->priority);

	s->prio = dst_prio;

	if (dst_prio != curr_prio) {
		list_move_tail(&s->ready_node, &sp->prio_lists[dst_prio]);

		bitmap_set_bit(sp->prio_bitmap, dst_prio);
		if (list_empty(&sp->prio_lists[curr_prio]))
			bitmap_clear_bit(sp->prio_bitmap, curr_prio);
	}
}

static inline void sched_update_curr
(
	struct sched_priv *sp, struct sched *curr
)
{
	int policy = 0;
	int prio = 0;
	int prio_min = 0;
	int consumed = 0;

	if (!curr)
		return;

	policy = curr->policy;

	if (policy == SCHED_FIFO)
		return;

	if (policy == SCHED_RR) {
		sched_change_prio(sp, curr, curr->prio);
		return;
	}

	/*
	 * SCHED_OTHER
	 */
	prio = curr->prio;
	prio_min = SCHED_PRIO_MIN + 1;
	consumed = curr->prio_consumed;

	/*
	 * every SCHED_OTHER entity cloud continuously run at least (0.25)ms
	 */
	if (consumed < SCHED_WEIGHT_PERLEVEL)
		return;

	while (consumed >= SCHED_WEIGHT_PERLEVEL) {
		consumed -= SCHED_WEIGHT_PERLEVEL;
		prio--;
	}

	/*
	 * every SCHED_OTHER entity will
	 * undergo the bottom priority
	 */
	if (prio < prio_min)
		prio = prio_min;

	sched_change_prio(sp, curr, prio);
	curr->prio_consumed = consumed;
}

static inline struct sched *sched_pick_next
(
	struct sched_priv *sp
)
{
	int idx = -1;
	struct sched *s = NULL;

	s = sp->archops->pick(sp);

	idx = bitmap_fls(sp->prio_bitmap,
			ARRAY_SIZE(sp->prio_bitmap));

	if (s && idx < SCHED_PRIO_MAX - 1)
		return s;

	/*
	 * To enhance the performance, we will not
	 * use list_first_entry().
	 * Because:
	 * 1. .next is impossible to be NULL.
	 * 2. the type is sure correct, no need to check.
	 * 3. offsetof(struct sched, node) is zero.
	 */
	if (likely(idx >= 0))
		return (struct sched *)sp->prio_lists[idx].next;

	return sp->idle;
}

static inline struct sched *sched_pick_global(
	struct sched_priv *currsp)
{
	struct sched *s = NULL, *_s = NULL;
	struct sched_priv *sp = NULL, *_sp = NULL;
	struct list_head *lists = NULL;
	unsigned int busy_factor = 1, ready_num = 0;
	struct sched_gd *gd = sched_gd();
	unsigned int cpu = currsp->pc->id;
	int idx = SCHED_PRIO_MAX;

	spin_unlock(&currsp->lock);
	spin_lock(&gd->lock);
	spin_lock(&currsp->lock);

	/* pick a most busy cpu */
	list_for_each_entry(_sp, &gd->cpus, node) {
		ready_num = _sp->ready_num;
		if (ready_num > busy_factor) {
			busy_factor = ready_num;
			sp = _sp;
		}
	}
	if (sp == currsp || sp == NULL) {
		spin_unlock(&gd->lock);
		return NULL;
	}

	spin_lock(&sp->lock);

	lists = sp->prio_lists;

	do {
		list_for_each_entry(_s, &lists[idx], ready_node) {
			if (cpu_affinity_isset(_s->affinity, cpu) && (_s != sp->curr)) {
				s = _s;
				break;
			}
		}
	} while (!s && (--idx > 0));

	if (s) {
		sched_list_del(sp, s);
		sched_idlecpu_inc(sp, gd);
		__sched_sp_del(sp, s);

		__sched_sp_add(currsp, s);
		sched_list_add(currsp, s);
		sched_idlecpu_dec(currsp);
	}

	spin_unlock(&sp->lock);
	spin_unlock(&gd->lock);
	return s;
}

static inline struct sched_priv *__sched_pick_mostidle_cpu(
	struct sched_gd *gd)
{
	struct sched_priv *sp = NULL, *ret = NULL;
	unsigned int busy_factor = INT_MAX;

	sp = list_first_entry_or_null(&gd->idle_cpus,
				struct sched_priv, idle_node);
	if (sp != NULL)
		return sp;

	list_for_each_entry(sp, &gd->cpus, node) {
		if (sp->ready_num < busy_factor) {
			busy_factor = sp->ready_num;
			ret = sp;
		}
	}

	return ret;
}

static inline struct sched_priv *sched_pick_affinity_idle_cpu(
	struct sched *s, struct sched_gd *gd)
{
	struct sched_priv *sp = NULL, *ret = NULL;

	spin_lock(&gd->idle_lock);

	list_for_each_entry(sp, &gd->idle_cpus, idle_node) {
		if (cpu_affinity_isset(s->affinity, sp->pc->id)) {
			ret = sp;
			break;
		}
	}

	spin_unlock(&gd->idle_lock);

	return ret;
}

static inline struct sched_priv *__sched_pick_affinity_cpu(
	struct sched *s, struct sched_gd *gd)
{
	struct sched_priv *sp = NULL, *ret = NULL;

#if CONFIG_NR_CPUS <= 16
	unsigned int busy_factor = INT_MAX;

	sp = sched_pick_affinity_idle_cpu(s, gd);
	if (sp != NULL)
		return sp;

	list_for_each_entry(sp, &gd->cpus, node) {
		if (!cpu_affinity_isset(s->affinity, sp->pc->id))
			continue;
		if (sp->ready_num < busy_factor) {
			busy_factor = sp->ready_num;
			ret = sp;
		}
	}

	return ret;
#else
	ret = sched_pick_affinity_idle_cpu(s, gd);

	if (ret == NULL) {
		list_for_each_entry(sp, &gd->cpus, node) {
			if (cpu_affinity_isset(s->affinity, sp->pc->id)) {
				list_move_tail(&sp->node, &gd->cpus);
				ret = sp;
				break;
			}
		}
	}

	return ret;
#endif
}

/*
 * pick the suitable processor
 */
static inline struct sched_priv *sched_pick_cpu(
	struct sched_gd *gd, struct sched_priv *currsp,
	struct sched *s)
{
	struct sched_priv *ret = s->sp;

#if (CONFIG_NR_CPUS > 1)
	if (s->bind)
		return ret;

	if (ret->ready_num != 0) {
		ret = __sched_pick_affinity_cpu(s, gd);
		if (ret == NULL)
			ret = __sched_pick_mostidle_cpu(gd);
	}
#endif

	return ret;
}

#endif
