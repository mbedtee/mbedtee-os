/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * DTB (Device Tree Blob) read-only parser
 */

#ifndef _OF_DTB_H
#define _OF_DTB_H

#include <defs.h>
#include <stdint.h>
#include <stddef.h>

/*
 * DTB magic number and token tags
 */
#define DTB_MAGIC		0xd00dfeed
#define DTB_TOK_NODE_BEGIN	0x1
#define DTB_TOK_NODE_END	0x2
#define DTB_TOK_PROP		0x3
#define DTB_TOK_NOP		0x4
#define DTB_TOK_END		0x9

/*
 * DTB binary header (all fields are big-endian)
 */
struct dtb_header {
	uint32_t magic;
	uint32_t blob_size;
	uint32_t struct_off;
	uint32_t strings_off;
	uint32_t rsvmap_off;
	uint32_t version;
	uint32_t compat_version;
	uint32_t boot_cpuid;
	uint32_t strings_size;
	uint32_t struct_size;
};

/*
 * Read DTB total size from header
 */
uint32_t dtb_total_size(const void *dtb);

/*
 * Validate DTB header (magic, version, size)
 * Returns 0 on success, -1 on failure
 */
int dtb_check(const void *dtb);

/*
 * Get the name of a node at the given struct-block offset
 * Returns pointer to the name string, NULL on error
 * If out_len is not NULL, *out_len is set to name length
 */
const char *dtb_node_name(const void *dtb, int pos, int *out_len);

/*
 * Lookup a property by name (with explicit name length) within a node
 * Returns pointer to property data, NULL if not found
 * If out_len is not NULL, *out_len is set to property data length
 */
const void *dtb_get_prop_len(const void *dtb, int pos,
	const char *key, int keylen, int *out_len);

/*
 * Lookup a property by C-string name within a node
 * Returns pointer to property data, NULL if not found
 * If out_len is not NULL, *out_len is set to property data length
 */
const void *dtb_get_prop(const void *dtb, int pos,
	const char *key, int *out_len);

/*
 * Get the phandle of a node (reads "phandle" or "linux,phandle")
 * Returns 0 if no phandle
 */
uint32_t dtb_node_phandle(const void *dtb, int pos);

/*
 * Get the offset of the first direct child of a node
 * Returns child offset, or -1 if no children
 */
int dtb_first_child(const void *dtb, int parent_pos);

/*
 * Get the offset of the next sibling node (same depth)
 * Returns sibling offset, or -1 if no more siblings
 */
int dtb_next_child(const void *dtb, int pos);

/*
 * Find the next node whose "compatible" property contains
 * the given string. Starts searching after 'start_pos'.
 * Returns node offset, or -1 if not found
 */
int dtb_find_compatible(const void *dtb, int start_pos,
	const char *compat);

/*
 * Iterate over all direct children of a parent node
 */
#define dtb_for_each_child(child, dtb, parent_pos)	\
	for (child = dtb_first_child(dtb, parent_pos);	\
	     child >= 0;				\
	     child = dtb_next_child(dtb, child))

#endif
