/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * List implementation @ bidirectional nodes
 */

#ifndef _LIST_H
#define _LIST_H

#include <defs.h>
#include <sys/cdefs.h>

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(x) { &(x), &(x) }

#define LIST_HEAD(x) \
	struct list_head x = LIST_HEAD_INIT(x)

static __always_inline int list_empty(
	struct list_head *h)
{
	return h == h->next;
}

static __always_inline void INIT_LIST_HEAD(
	struct list_head *h)
{
	h->prev = h;
	h->next = h;
}

static __always_inline void list_add
(
	struct list_head *n,
	struct list_head *h
)
{
	struct list_head *next = h->next;

	n->prev = h;
	n->next = next;
	next->prev = n;
	h->next = n;
}

static __always_inline void list_add_tail
(
	struct list_head *n,
	struct list_head *h
)
{
	struct list_head *prev = h->prev;

	n->next = h;
	n->prev = prev;
	prev->next = n;
	h->prev = n;
}

static __always_inline void __list_del_entry(struct list_head *n)
{
	struct list_head *prev = n->prev;
	struct list_head *next = n->next;

	next->prev = prev;
	prev->next = next;
}

static __always_inline void list_del(struct list_head *n)
{
	__list_del_entry(n);
	INIT_LIST_HEAD(n);
}

static __always_inline void list_move
(
	struct list_head *n,
	struct list_head *h
)
{
	__list_del_entry(n);
	list_add(n, h);
}

static __always_inline void list_move_tail
(
	struct list_head *n,
	struct list_head *h
)
{
	__list_del_entry(n);
	list_add_tail(n, h);
}

static inline void list_rotate_left(struct list_head *h)
{
	if (!list_empty(h))
		list_move_tail(h->next, h);
}

static inline void list_bulk_move_tail(struct list_head *h,
	struct list_head *first, struct list_head *last)
{
	first->prev->next = last->next;
	last->next->prev = first->prev;

	h->prev->next = first;
	first->prev = h->prev;

	last->next = h;
	h->prev = last;
}

#define list_entry(p, t, m) container_of(p, t, m)

#define list_first_entry(p, t, m) \
	list_entry((p)->next, t, m)

#define list_first_entry_or_null(p, t, m) \
	(!list_empty(p) ? list_first_entry(p, t, m) : NULL)

#define list_last_entry(p, t, m) \
	list_entry((p)->prev, t, m)

#define list_last_entry_or_null(p, t, m) \
	(!list_empty(p) ? list_last_entry(p, t, m) : NULL)

#define list_next_entry(p, m) \
	list_entry((p)->m.next, typeof(*(p)), m)

#define list_prev_entry(p, m) \
	list_entry((p)->m.prev, typeof(*(p)), m)

#define list_for_each_entry(p, h, m) \
	if (!list_empty(h)) \
		for (p = list_first_entry(h, typeof(*(p)), m); \
			&(p)->m != (h); p = list_next_entry(p, m))

#define list_for_each_entry_safe(p, n, h, m) \
	if (!list_empty(h)) \
		for (p = list_first_entry(h, typeof(*(p)), m), \
			n = list_next_entry(p, m); &(p)->m != (h); \
			p = n, n = list_next_entry(n, m))

#define list_for_each_entry_reverse(p, h, m) \
	if (!list_empty(h)) \
		for (p = list_last_entry(h, typeof(*(p)), m); \
			&(p)->m != (h); p = list_prev_entry(p, m))

#define list_for_each_entry_safe_reverse(p, n, h, m) \
	if (!list_empty(h)) \
		for (p = list_last_entry(h, typeof(*(p)), m), \
			n = list_prev_entry(p, m); &(p)->m != (h); \
			p = n, n = list_prev_entry(n, m))

#define list_for_each_entry_from(p, h, m) \
	for (; &(p)->m != (h); p = list_next_entry(p, m))

#define list_for_each_entry_safe_from(p, n, h, m) \
	for (n = list_next_entry(p, m); &(p)->m != (h); \
		p = n, n = list_next_entry(n, m))

#define list_for_each_entry_from_reverse(p, h, m) \
	for (; &(p)->m != (h); p = list_prev_entry(p, m))

#define list_for_each_entry_safe_from_reverse(p, n, h, m) \
	for (n = list_prev_entry(p, m); &(p)->m != (h); \
		p = n, n = list_prev_entry(n, m))

#define list_for_each_entry_continue(p, h, m) \
	for (p = list_next_entry(p, m); &(p)->m != (h); \
	     p = list_next_entry(p, m))

#define list_for_each_entry_safe_continue(p, n, h, m) \
	for (p = list_next_entry(p, m), n = list_next_entry(p, m); \
	     &(p)->m != (h); p = n, n = list_next_entry(n, m))

#define list_for_each_entry_continue_reverse(p, h, m) \
	for (p = list_prev_entry(p, m); &(p)->m != (h); \
	     p = list_prev_entry(p, m))

#define list_for_each_entry_safe_continue_reverse(p, n, h, m) \
	for (p = list_prev_entry(p, m), n = list_prev_entry(p, m); \
	     &(p)->m != (h); p = n, n = list_prev_entry(n, m))

#endif
