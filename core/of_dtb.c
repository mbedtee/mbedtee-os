// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * DTB (Device Tree Blob) read-only parser
 */

#include <of_dtb.h>
#include <string.h>

/*
 * Read a big-endian 32-bit word from an arbitrary address
 */
static uint32_t rd32be(const void *addr)
{
	const uint8_t *d = (const uint8_t *)addr;

	return ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) |
	       ((uint32_t)d[2] << 8) | (uint32_t)d[3];
}

/*
 * Get the header field value
 */
static inline uint32_t hdr_field(const void *dtb, int field_off)
{
	return rd32be((const char *)dtb + field_off);
}

/*
 * Pointer into the struct block at a given offset
 */
static inline const void *struct_at(const void *dtb, int pos)
{
	return (const char *)dtb + hdr_field(dtb,
		offsetof(struct dtb_header, struct_off)) + pos;
}

/*
 * Pointer into the strings block at a given offset
 */
static inline const char *str_at(const void *dtb, int soff)
{
	return (const char *)dtb + hdr_field(dtb,
		offsetof(struct dtb_header, strings_off)) + soff;
}

/*
 * Align an offset up to a 4-byte boundary
 */
#define ALIGN4(x)	(((x) + 3) & ~3)

uint32_t dtb_total_size(const void *dtb)
{
	return hdr_field(dtb, offsetof(struct dtb_header, blob_size));
}

int dtb_check(const void *dtb)
{
	uint32_t mag = hdr_field(dtb, offsetof(struct dtb_header, magic));
	uint32_t ver = hdr_field(dtb, offsetof(struct dtb_header, version));
	uint32_t cver = hdr_field(dtb, offsetof(struct dtb_header, compat_version));
	uint32_t sz = dtb_total_size(dtb);

	if (mag != DTB_MAGIC)
		return -1;

	if (ver < 0x02 || cver > 0x11)
		return -1;

	if (sz < sizeof(struct dtb_header))
		return -1;

	return 0;
}

/*
 * Skip over one token and its payload, advancing 'pos'.
 * Returns the token type skipped (or DTB_TOK_END on error).
 */
static uint32_t skip_token(const void *dtb, int pos, int *next)
{
	uint32_t tok = rd32be(struct_at(dtb, pos));

	pos += 4;

	switch (tok) {
	case DTB_TOK_NODE_BEGIN: {
		const char *nm = (const char *)struct_at(dtb, pos);

		pos += strlen(nm) + 1;
		break;
	}
	case DTB_TOK_PROP: {
		uint32_t dlen = rd32be(struct_at(dtb, pos));

		pos += 4 + 4 + dlen; /* val_len + name_off + data */
		break;
	}
	case DTB_TOK_NODE_END:
	case DTB_TOK_NOP:
	case DTB_TOK_END:
		break;
	default:
		*next = -1;
		return DTB_TOK_END;
	}

	*next = ALIGN4(pos);
	return tok;
}

/*
 * Walk to the next node in depth-first order.
 * If lvl is not NULL, it tracks the relative depth change.
 * Returns the struct-block offset of the next NODE_BEGIN, or -1.
 */
static int walk_next_node(const void *dtb, int pos, int *lvl)
{
	int cursor = 0;
	uint32_t tok;

	/* Advance past the current NODE_BEGIN */
	if (pos >= 0) {
		tok = skip_token(dtb, pos, &cursor);
		if (tok != DTB_TOK_NODE_BEGIN)
			return -1;
	}

	for (;;) {
		pos = cursor;
		tok = skip_token(dtb, pos, &cursor);
		if (cursor < 0)
			return -1;

		if (tok == DTB_TOK_NODE_BEGIN) {
			if (lvl)
				(*lvl)++;
			return pos;
		}
		if (tok == DTB_TOK_NODE_END) {
			if (lvl && ((--(*lvl)) < 0))
				return cursor;
		}
		if (tok == DTB_TOK_END)
			return -1;
		/* DTB_TOK_PROP / DTB_TOK_NOP: keep scanning */
	}
}

const char *dtb_node_name(const void *dtb, int pos, int *out_len)
{
	const char *nm = NULL;

	if (rd32be(struct_at(dtb, pos)) != DTB_TOK_NODE_BEGIN) {
		if (out_len)
			*out_len = -1;
		return NULL;
	}

	nm = (const char *)struct_at(dtb, pos + 4);

	if (out_len)
		*out_len = strlen(nm);
	return nm;
}

const void *dtb_get_prop_len(const void *dtb, int pos,
	const char *key, int keylen, int *out_len)
{
	int cursor = 0;
	uint32_t tok;
	uint32_t vlen = 0;
	uint32_t noff = 0;
	const char *pname = NULL;

	if (pos < 0) {
		if (out_len)
			*out_len = 0;
		return NULL;
	}

	/* Step over the NODE_BEGIN token */
	tok = skip_token(dtb, pos, &cursor);
	if (tok != DTB_TOK_NODE_BEGIN) {
		if (out_len)
			*out_len = 0;
		return NULL;
	}

	/* Scan properties belonging to this node */
	while (cursor >= 0) {
		pos = cursor;
		tok = rd32be(struct_at(dtb, pos));

		if (tok == DTB_TOK_NOP) {
			skip_token(dtb, pos, &cursor);
			continue;
		}
		if (tok != DTB_TOK_PROP)
			break;

		/* Property layout: tok(4) + val_len(4) + name_off(4) + data */
		vlen = rd32be(struct_at(dtb, pos + 4));
		noff = rd32be(struct_at(dtb, pos + 8));
		pname = str_at(dtb, noff);

		if ((int)strlen(pname) == keylen &&
		    memcmp(pname, key, keylen) == 0) {
			if (out_len)
				*out_len = vlen;
			return struct_at(dtb, pos + 12);
		}

		skip_token(dtb, pos, &cursor);
	}

	if (out_len)
		*out_len = 0;
	return NULL;
}

const void *dtb_get_prop(const void *dtb, int pos,
	const char *key, int *out_len)
{
	return dtb_get_prop_len(dtb, pos, key, strlen(key), out_len);
}

uint32_t dtb_node_phandle(const void *dtb, int pos)
{
	int bytes = 0;
	const uint32_t *val;

	val = (const uint32_t *)dtb_get_prop(dtb, pos, "phandle", &bytes);
	if (!val || bytes != sizeof(uint32_t)) {
		val = (const uint32_t *)dtb_get_prop(dtb, pos,
				"linux,phandle", &bytes);
		if (!val || bytes != sizeof(uint32_t))
			return 0;
	}

	return be32_to_cpu(*val);
}

int dtb_first_child(const void *dtb, int parent_pos)
{
	int lvl = 0;
	int child = walk_next_node(dtb, parent_pos, &lvl);

	if (child < 0 || lvl != 1)
		return -1;
	return child;
}

int dtb_next_child(const void *dtb, int pos)
{
	int lvl = 1;

	do {
		pos = walk_next_node(dtb, pos, &lvl);
		if (pos < 0 || lvl < 1)
			return -1;
	} while (lvl > 1);

	return pos;
}

/*
 * Check if a stringlist (concatenated NUL-terminated strings)
 * contains a specific entry.
 */
static int strlist_has(const char *list, int list_len, const char *entry)
{
	int elen = strlen(entry);

	while (list_len >= elen) {
		const char *z = NULL;

		if (memcmp(list, entry, elen + 1) == 0)
			return 1;

		z = memchr(list, '\0', list_len);

		if (!z)
			return 0;

		list_len -= (z - list) + 1;
		list = z + 1;
	}

	return 0;
}

int dtb_find_compatible(const void *dtb, int start_pos,
	const char *compat)
{
	int pos;

	for (pos = walk_next_node(dtb, start_pos, NULL);
	     pos >= 0;
	     pos = walk_next_node(dtb, pos, NULL)) {
		int bytes = 0;
		const char *val = (const char *)dtb_get_prop(
				dtb, pos, "compatible", &bytes);

		if (val && bytes > 0 && strlist_has(val, bytes, compat))
			return pos;
	}

	return -1;
}
