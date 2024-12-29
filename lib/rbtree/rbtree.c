// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * red-black-tree
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "rbtree.h"

#define RB_RED 0
#define RB_BLACK 1ul
#define rb_color(n) ((n)->parent_color & RB_BLACK)
#define rb_is_red(n) (rb_color(n) == RB_RED)
#define rb_is_black(n) (rb_color(n) == RB_BLACK)
#define rb_set_black(n) ((n)->parent_color |= RB_BLACK)
#define rb_set_red(n) ((n)->parent_color &= ~RB_BLACK)
#define rb_set_parent(n, parent) ((n)->parent_color = rb_color(n) \
	| (unsigned long)(parent))
#define rb_set_parent_color(n, parent, color) ((n)->parent_color = (color) \
	| (unsigned long)(parent))

static inline void rb_replace_child(struct rb_node *ori,
	struct rb_node **root, struct rb_node *new, struct rb_node *parent)
{
	if (parent) {
		if (parent->left == ori)
			parent->left = new;
		else
			parent->right = new;
	} else {
		*root = new;
	}

	if (new)
		new->parent_color = ori->parent_color;
}

static void rb_rotate_left(struct rb_node *node, struct rb_node **root)
{
	struct rb_node *new = node->right;
	struct rb_node *tmp = new->left;
	unsigned long color = rb_color(new);

	new->left = node;
	node->right = tmp;
	if (tmp)
		rb_set_parent(tmp, node);

	rb_replace_child(node, root, new, rb_parent(node));
	rb_set_parent_color(node, new, color);
}

static void rb_rotate_right(struct rb_node *node, struct rb_node **root)
{
	struct rb_node *new = node->left;
	struct rb_node *tmp = new->right;
	unsigned long color = rb_color(new);

	new->right = node;
	node->left = tmp;
	if (tmp)
		rb_set_parent(tmp, node);

	rb_replace_child(node, root, new, rb_parent(node));
	rb_set_parent_color(node, new, color);
}

void rb_insert(struct rb_node *node, struct rb_node **root)
{
	struct rb_node *parent = NULL, *grandparent = NULL;

	rb_set_red(node);

	for (;;) {
		parent = rb_parent(node);

		if (!parent) {
			rb_set_parent_color(node, NULL, RB_BLACK);
			break;
		}

		if (rb_is_black(parent))
			break;

		grandparent = rb_parent(parent);
		struct rb_node *uncle = grandparent->left;

		if (uncle != parent) {
			if (uncle && rb_is_red(uncle)) {
				rb_set_black(uncle);
				rb_set_black(parent);
				rb_set_red(grandparent);
				node = grandparent;
				continue;
			}

			if (parent->left == node)
				rb_rotate_right(parent, root);

			rb_rotate_left(grandparent, root);
		} else {
			uncle = grandparent->right;

			if (uncle && rb_is_red(uncle)) {
				rb_set_black(uncle);
				rb_set_black(parent);
				rb_set_red(grandparent);
				node = grandparent;
				continue;
			}

			if (parent->right == node)
				rb_rotate_left(parent, root);

			rb_rotate_right(grandparent, root);
		}

		break;
	}
}

static void rb_del_fixup(struct rb_node *parent,
	struct rb_node *node, struct rb_node **root)
{
	struct rb_node *sibling = NULL;
	struct rb_node *rchild = NULL;
	struct rb_node *lchild = NULL;
	bool recursion = false;

	if (parent->right != node) {
		sibling = parent->right;

		if (rb_is_red(sibling)) {
			rb_rotate_left(parent, root);
			sibling = parent->right;
		}

		rchild = sibling->right;
		lchild = sibling->left;
		if (rchild && rb_is_red(rchild)) {
			rb_set_black(rchild);
			rb_rotate_left(parent, root);
		} else if (lchild && rb_is_red(lchild)) {
			rb_rotate_right(sibling, root);
			rb_rotate_left(parent, root);
			rb_set_black(sibling);
		} else {
			recursion = true;
		}
	} else {
		sibling = parent->left;

		if (rb_is_red(sibling)) {
			rb_rotate_right(parent, root);
			sibling = parent->left;
		}

		lchild = sibling->left;
		rchild = sibling->right;
		if (lchild && rb_is_red(lchild)) {
			rb_set_black(lchild);
			rb_rotate_right(parent, root);
		} else if (rchild && rb_is_red(rchild)) {
			rb_rotate_left(sibling, root);
			rb_rotate_right(parent, root);
			rb_set_black(sibling);
		} else {
			recursion = true;
		}
	}

	if (recursion) {
		rb_set_red(sibling);

		struct rb_node *grandparent = rb_parent(parent);

		if (grandparent && rb_is_black(parent))
			rb_del_fixup(grandparent, parent, root);
		else
			rb_set_black(parent);
	}
}

void rb_del(struct rb_node *node, struct rb_node **root)
{
	struct rb_node *parent = rb_parent(node);
	struct rb_node *lchild = node->left;
	struct rb_node *rchild = node->right;
	struct rb_node *fixup = NULL;

	if (rb_empty(node))
		return;

	if (!lchild) {
		rb_replace_child(node, root, rchild, parent);
		if (!rchild && rb_is_black(node))
			fixup = parent;
	} else if (!rchild) {
		rb_replace_child(node, root, lchild, parent);
	} else {
		struct rb_node *successor = rchild;
		struct rb_node *p2 = NULL, *rchild2 = NULL;

		if (!successor->left) {
			rchild2 = successor->right;

			if (rchild2)
				rb_set_black(rchild2);
			else if (rb_is_black(successor))
				fixup = successor;

			rb_replace_child(node, root, successor, parent);

			successor->left = lchild;
			rb_set_parent(lchild, successor);
		} else {
			while (successor->left)
				successor = successor->left;

			p2 = rb_parent(successor);
			rchild2 = successor->right;

			p2->left = rchild2;
			if (rchild2)
				rb_set_parent_color(rchild2, p2, RB_BLACK);
			else if (rb_is_black(successor))
				fixup = p2;

			rb_replace_child(node, root, successor, parent);

			successor->left = lchild;
			successor->right = rchild;
			rb_set_parent(lchild, successor);
			rb_set_parent(rchild, successor);
		}
	}

	if (fixup)
		rb_del_fixup(fixup, NULL, root);

	rb_node_init(node);
}


struct rb_node *rb_prev(const struct rb_node *n)
{
	struct rb_node *parent = NULL;

	if (rb_empty(n))
		return NULL;

	if (n->left) {
		n = n->left;

		while (n->right)
			n = n->right;

		return (struct rb_node *)n;
	}

	parent = rb_parent(n);
	while (parent && parent->left == n) {
		n = parent;
		parent = rb_parent(n);
	}

	return parent;
}

struct rb_node *rb_next(const struct rb_node *n)
{
	struct rb_node *parent = NULL;

	if (rb_empty(n))
		return NULL;

	if (n->right) {
		n = n->right;

		while (n->left)
			n = n->left;

		return (struct rb_node *)n;
	}

	parent = rb_parent(n);
	while (parent && (parent->right == n)) {
		n = parent;
		parent = rb_parent(n);
	}

	return parent;
}

static struct rb_node *left_deepest_node(const struct rb_node *n)
{
	while (n) {
		if (n->left)
			n = n->left;
		else if (n->right)
			n = n->right;
		else
			break;
	}

	return (struct rb_node *)n;
}

struct rb_node *rb_next_postorder(const struct rb_node *n)
{
	struct rb_node *parent = NULL;

	parent = rb_parent(n);
	if (parent && (n == parent->left) && parent->right)
		return left_deepest_node(parent->right);
	else
		return parent;
}

struct rb_node *rb_first_postorder(const struct rb_node *root)
{
	return left_deepest_node(root);
}
