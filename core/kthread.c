// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * kernel thread implementation
 */

#include <percpu.h>
#include <trace.h>
#include <sched.h>
#include <list.h>
#include <kmalloc.h>
#include <string.h>
#include <sleep.h>
#include <ida.h>
#include <page.h>
#include <kthread.h>
#include <errno.h>

static void kthread_entry(thread_func_t func, void *data)
{
	long ret = 0;

	if (func) {
		ret = func(data);
		wakeup_notify(&current->join_q, ret);
	}

	sched_kexit();
}

/*
 * Cleanup the resources of the exited kthread
 */
static void kthread_destroy(struct work *w)
{
	if (w) {
		struct thread *t = container_of(w,
				struct thread, destroy);

		thread_cleanup_run(t);

		wakeup(&t->join_q);

		waitqueue_flush(&t->join_q);

		kfree(t->brstack);

		sched_free_id(t->id);

		thread_free(t);
	}
}

/*
 * Create a kernel thread on current CPU
 * @func - thread function to run.
 * @data - data pointer for the func().
 * @stack_s - kernel thread's stack size.
 * @namefmt - name of this thread with printk-style.
 * (No more 64 characters)
 */
int __kthread_create(thread_func_t func, void *data,
	size_t stack_s, const char *namefmt, ...)
{
	int ret = -1;
	struct thread *t = NULL;
	va_list args;
	char name[THREAD_NAME_LEN - 5];

	if (!func || !namefmt)
		return -EINVAL;

	t = thread_alloc(stack_s);
	if (!t)
		return -ENOMEM;

	va_start(args, namefmt);
	vsnprintf(name, sizeof(name), namefmt, args);
	va_end(args);

	t->proc = kproc();
	INIT_LIST_HEAD(&t->mutexs);
	INIT_LIST_HEAD(&t->wqnodes);
	INIT_LIST_HEAD(&t->polls);
	waitqueue_init(&t->wait_q);
	waitqueue_init(&t->join_q);
	mutex_init(&t->mlock);
	INIT_WORK(&t->destroy, kthread_destroy);

	/*
	 * kthread default priority is a little
	 * bit higher than the userthread's max
	 */
	ret = sched_install(t, SCHED_OTHER,
				SCHED_PRIO_DEFAULT);
	if (ret != 0)
		goto out;

	snprintf(t->name, sizeof(t->name), "%s@%04d",
			name, t->id);

	ret = sched_entry_init(t->id,
		kthread_entry, func, data);

out:
	if (ret != 0) {
		sched_uninstall(t->sched);
		thread_free(t);
		return ret;
	}
	return t->id;
}
