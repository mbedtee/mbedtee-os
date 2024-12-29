// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * provide threads info via debugfs
 */

#include <timer.h>
#include <trace.h>
#include <thread.h>
#include <sched.h>
#include <debugfs.h>
#include <__pthread.h>

#include "sched_priv.h"

static int sched_debugfs_info_read(struct debugfs_file *d)
{
	struct sched *dst = NULL;
	struct sched_priv *sp = NULL;
	struct sched_gd *gd = sched_gd();
	struct thread *t = NULL;
	unsigned long flags = 0;
	uint64_t cur_cycles = 0;
	unsigned short cnts[6] = {0};
	unsigned short total = 0, i = 0, aligned = false, stat = 0;
	struct timespec tmp;

	static const char * const sched_type[] = {
		"OTHER", "FIFO", "RR  "
	};

	debugfs_printf(d, "TID|PID@CPU\tSTATE\tSG|UC|KC|E|B|A|PRI@POLICY\tRUNTIME\t\t\tLOADING\t\tNAME\n");

	flags = sched_hold_all(gd);

	read_time(&tmp);
	cur_cycles = time_to_cycles(&tmp);

	list_for_each_entry(dst, &gd->sl, gd_node) {
		sp = dst->sp;
		t = dst->thread;

		/* thread id */
		debugfs_printf(d, "%04d|%04d@%d\t", dst->id,
				t->proc->id, sp->pc->id);

		/* state */
		stat = dst->s_stat == SCHED_EXITING ? SCHED_EXIT : dst->state;
		debugfs_printf(d, "%s\t", sched_state(stat));
		cnts[stat]++;

		/* sched priority and policy */
		debugfs_printf(d, "%02d|%02d|%02d|%01d|%01d|%lx|%02d|%02d@%s\t",
			sighandling(t), t->tuser ? t->tuser->critical : 0, t->critical,
			t->tuser ? t->tuser->exiting : 0, dst->bind, *(long *)dst->affinity,
			dst->prio, dst->priority, sched_type[dst->policy]);

		/* runtime */
		cycles_to_time(dst->overall, &tmp);
		debugfs_printf(d, "%09lu.%09lus\t",
			(unsigned long)tmp.tv_sec, tmp.tv_nsec);

		/* overall loading and instantaneous loading */
		debugfs_printf(d, "%03d.%02d%% %03d.%02d%%\t", (int)(dst->overall * 100 / cur_cycles),
			(int)((dst->overall * 100 % cur_cycles) * 100 / cur_cycles),
			(int)((uint64_t)dst->lruntime * 100 / sp->lruntime),
			(int)((((uint64_t)dst->lruntime * 100) % sp->lruntime) * 100 / sp->lruntime));

		/* App name */
		debugfs_printf(d, "%s\n", t->name);
		total++;
	}

	debugfs_printf(d, "Current: %d/%d", total, SCHED_ID_END);
	for (i = 0; i < SCHED_STAT_MAX; i++)
		debugfs_printf(d, " | %04d %s", cnts[i], sched_state(i));
	debugfs_printf(d, "\n");

	debugfs_printf(d, "Cpuidle:");
	for_each_online_cpu(i) {
		sp = &__sched_priv[i];
		dst = sp->idle;
		if (dst == NULL)
			continue;

		/* idle thread's instantaneous loading */
		debugfs_printf(d, " CPU%d=%02d.%02d%%",
			i, (int)((uint64_t)dst->lruntime * 100 / sp->lruntime),
			(int)((((uint64_t)dst->lruntime * 100) % sp->lruntime) * 100 / sp->lruntime));
		aligned = ((i + 1) % 8 == 0);
		if (aligned)
			debugfs_printf(d, "\n");
	}
	if (!aligned)
		debugfs_printf(d, "\n");

	debugfs_printf(d, "ReadyCnt:");
	for_each_online_cpu(i) {
		sp = &__sched_priv[i];
		debugfs_printf(d, " CPU%d=[%d/%d]", i, sp->ready_num, sp->total_num);
		aligned = ((i + 1) % 8 == 0);
		if (aligned)
			debugfs_printf(d, "\n");
	}
	if (!aligned)
		debugfs_printf(d, "\n");

	/* check the show-waiting flag */
	if (d->priv) {
		struct waitqueue_node *n = NULL;

		list_for_each_entry(dst, &gd->sl, gd_node) {
			t = dst->thread;
			if (dst->state == SCHED_WAITING) {
				list_for_each_entry(n, &t->wqnodes, tnode) {
					debugfs_printf(d, "%s @ %s() line %d p=%p\n",
						t->name, n->fnname ? n->fnname : "null",
						n->linenr, n->priv);
				}
			}
		}
	}

	debugfs_printf(d, "\n");

	sched_put_all(gd, flags);
	return 0;
}

static ssize_t sched_debugfs_info_write(struct debugfs_file *d,
	const void *option, size_t cnt)
{
	/* set the show-waiting flag */
	if ((cnt == 1) && strcmp(option, "w") == 0) {
		d->priv = (void *)1ul;
		return cnt;
	}

	return -EINVAL;
}

static const struct debugfs_fops sched_debugfs_threads_ops = {
	.read = sched_debugfs_info_read,
	.write = sched_debugfs_info_write,
};

static void __init sched_debugfs_init(void)
{
	debugfs_create("/threads", &sched_debugfs_threads_ops);
}
MODULE_INIT(sched_debugfs_init);
