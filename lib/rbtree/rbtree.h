/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * red-black-tree
 */

#ifndef _RBTREE_H
#define _RBTREE_H

#include <defs.h>

struct rb_node {
	unsigned long parent_color;
	struct rb_node *left;
	struct rb_node *right;
};

#define rb_parent(n) ((struct rb_node *)((n)->parent_color & ~1ul))

#define rb_entry(ptr, type, member)	({   \
	void *__p = (void *)(ptr);                             \
	__p ? (type *)(__p - offsetof(type, member)) : NULL; })

/* faster version of rb_entry, assume ptr is non-null */
#define rb_entry_of(ptr, type, member) container_of(ptr, type, member)

#define RB_INIT_NODE(n) {(unsigned long)&(n), NULL, NULL}

/* just like the list_empty, introduced to avoid double-delete */
static __always_inline int rb_empty(const struct rb_node *n)
{
	/* might be already deleted ... */
	return (unsigned long)n == n->parent_color;
}

/*
 * just like the INIT_LIST_HEAD, rb_del()
 * calls this to avoid re-use this node in a rbtree
 */
static __always_inline void rb_node_init(struct rb_node *n)
{
	/* mark for deleted ... */
	n->parent_color = (unsigned long)n;
}

static __always_inline void rb_link_parent(struct rb_node *n,
	struct rb_node **lnk, struct rb_node *parent)
{
	(n)->left = (n)->right = NULL;
	(n)->parent_color = (unsigned long)(parent);
	*(lnk) = (n);
}

static __always_inline struct rb_node *rb_first(const struct rb_node *n)
{
	if (!n)
		return NULL;

	while (n->left)
		n = n->left;

	return (struct rb_node *)n;
}

static __always_inline struct rb_node *rb_last(const struct rb_node *n)
{
	if (!n)
		return NULL;

	while (n->right)
		n = n->right;

	return (struct rb_node *)n;
}

static __always_inline struct rb_node *rb_find(
	const void *key, struct rb_node *root,
	intptr_t (*cmp)(const void *key, const struct rb_node *n))
{
	while (root) {
		intptr_t result = cmp(key, root);

		if (result == 0)
			break;
		else if (result < 0)
			root = root->left;
		else
			root = root->right;
	}

	return root;
}

static __always_inline struct rb_node *rb_find_first(
	const void *key, struct rb_node *root,
	intptr_t (*cmp)(const void *key, struct rb_node *n))
{
	struct rb_node *first = NULL;

	while (root) {
		intptr_t result = cmp(key, root);

		if (result <= 0) {
			if (result == 0)
				first = root;
			root = root->left;
		} else
			root = root->right;
	}

	return first;
}

static __always_inline struct rb_node *rb_find_less(
	const void *key, struct rb_node *root,
	intptr_t (*cmp)(const void *key, const struct rb_node *n))
{
	while (root) {
		intptr_t result = cmp(key, root);

		if (result <= 0)
			break;
		else if (result < 0)
			root = root->left;
		else
			root = root->right;
	}

	return root;
}

extern void rb_insert(struct rb_node *node, struct rb_node **root);

static __always_inline void rb_add(
	struct rb_node *n, struct rb_node **root,
	intptr_t (*cmp)(const struct rb_node *, const struct rb_node *))
{
	intptr_t result = 0;
	struct rb_node **ppn = root, *parent = NULL;

	while (*ppn) {
		parent = *ppn;

		result = cmp(n, parent);
		if (result < 0)
			ppn = &parent->left;
		else
			ppn = &parent->right;
	}

	rb_link_parent(n, ppn, parent);
	rb_insert(n, root);
}

static __always_inline struct rb_node *rb_add_unique(
	struct rb_node *n, struct rb_node **root,
	intptr_t (*cmp)(const struct rb_node *, const struct rb_node *))
{
	intptr_t result = 0;
	struct rb_node **ppn = root, *parent = NULL;

	while (*ppn) {
		parent = *ppn;

		result = cmp(n, parent);

		if (result == 0)
			return parent;
		else if (result < 0)
			ppn = &parent->left;
		else
			ppn = &parent->right;
	}

	rb_link_parent(n, ppn, parent);
	rb_insert(n, root);
	return NULL;
}

void rb_del(struct rb_node *n, struct rb_node **root);

struct rb_node *rb_next(const struct rb_node *n);
struct rb_node *rb_prev(const struct rb_node *n);

struct rb_node *rb_first_postorder(const struct rb_node *root);
struct rb_node *rb_next_postorder(const struct rb_node *n);

#define rb_first_entry(root, type, member) \
	rb_entry(rb_first(root), type, member)

#define rb_last_entry(root, type, member) \
	rb_entry(rb_last(root), type, member)

#define rb_next_entry(pos, member) \
	rb_entry(rb_next(&(pos)->member), typeof(*(pos)), member)

#define rb_prev_entry(pos, member) \
	rb_entry(rb_prev(&(pos)->member), typeof(*(pos)), member)

#define rb_first_entry_postorder(root, type, member) \
	rb_entry(rb_first_postorder(root), type, member)

#define rb_next_entry_postorder(pos, member) \
	rb_entry(rb_next_postorder(&(pos)->member), typeof(*(pos)), member)

#define rb_for_each_entry(pos, root, member) \
	for ((pos) = rb_first_entry(root, typeof(*(pos)), member); \
	     (pos); (pos) = rb_next_entry(pos, member))

#define rb_for_each_entry_safe(pos, n, root, member) \
	for ((pos) = rb_first_entry(root, typeof(*(pos)), member), \
		(n) = (pos) ? rb_next_entry(pos, member) : NULL; (pos); (pos) = (n), \
		(n) = (n) ? rb_next_entry(n, member) : NULL)

#define rb_for_each_entry_reverse(pos, root, member) \
	for ((pos) = rb_last_entry(root, typeof(*(pos)), member); \
	     (pos); (pos) = rb_prev_entry(pos, member))

#define rb_for_each_entry_postorder(pos, root, member) \
	for ((pos) = rb_first_entry_postorder(root, typeof(*(pos)), member); \
	     (pos); (pos) = rb_next_entry_postorder(pos, member))

#define rb_for_each_entry_safe_postorder(pos, n, root, member) \
	for ((pos) = rb_first_entry_postorder(root, typeof(*(pos)), member), \
		(n) = (pos) ? rb_next_entry_postorder(pos, member) : NULL; (pos); (pos) = (n), \
		(n) = (n) ? rb_next_entry_postorder(n, member) : NULL)
#endif
