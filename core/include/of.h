/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Device Tree - Open Firmware Implementation
 */

#ifndef _OF_H
#define _OF_H

#include <list.h>
#include <kmap.h>
#include <stdint.h>
#include <device.h>

struct of_device_id {
	const char *name;
	const char *compat;
};

struct device_node {
	int offset;
	unsigned int phandle;
	struct of_device_id id;
	struct device_node *parent;
	struct device_node *next;
	struct list_head node;
	struct list_head child;
	struct device dev;
};

struct of_compat_init {
	const char *compat;
	int (*init)(struct device_node *dn);
};

/*
 * get device node of the specified name
 */
struct device_node *of_find_node_by_name(
	struct device_node *from, const char *name);

/*
 * get compatible device node
 */
struct device_node *of_find_compatible_node(
	struct device_node *from,
	const char *compat);

/*
 * match the compatible device node
 */
struct device_node *of_find_matching_node(
	struct device_node *from,
	const struct of_device_id *matches);

/*
 * get device node of the specified phandle
 */
struct device_node *of_find_node_by_phandle(unsigned int phandle);

/*
 * return count of u32 read on success
 * #mincnt - minium allowed count of the #propname
 * #maxcnt - maxium allowed count of the #propname
 * return -EOVERFLOW if the property elements cnt less than mincnt
 * return -EOVERFLOW if the property elements cnt big than maxcnt
 */
int of_property_read_variable_u32_array(struct device_node *dn,
	const char *propname, unsigned int *out, size_t mincnt, size_t maxcnt);

/*
 * return count of u32 read on success
 * #cnt - try to read at most #cnt of u32 from #propname
 */
int __of_property_read_u32_array(struct device_node *dn,
	const char *propname, unsigned int *out, size_t cnt);

/*
 * return 0 on success
 */
static inline int of_property_read_u32_array(struct device_node *dn,
	const char *propname, unsigned int *out, size_t cnt)
{
	int ret = -ENODATA;

	if (dn == NULL)
		return ret;

	ret = of_property_read_variable_u32_array(dn, propname, out, cnt, 0);

	return ret >= 0 ? 0 : ret;
}

static inline int of_property_read_u32(struct device_node *dn,
	const char *propname, unsigned int *out)
{
	return of_property_read_u32_array(dn, propname, out, 1);
}

static inline int of_property_read_s32_array(struct device_node *dn,
	const char *propname, int *out, int cnt)
{
	return of_property_read_u32_array(dn, propname, (unsigned int *)out, cnt);
}

static inline int of_property_read_s32(struct device_node *dn,
	const char *propname, int *out)
{
	return of_property_read_u32(dn, propname, (unsigned int *)out);
}

/*
 * get size of specified property (unit is specified by `elem_size`)
 */
int of_property_count_elems_of_size(const struct device_node *dn,
	const char *propname, int elem_size);

/*
 * get nr_cells of '#address-cells'
 */
int of_n_addr_cells(struct device_node *dn);

/*
 * get nr_cells of '#size-cells'
 */
int of_n_size_cells(struct device_node *dn);

/*
 * get nr_cells of '#interrupt-cells'
 */
int of_n_interrupt_cells(struct device_node *dn);

int of_irq_parse_one(struct device_node *dn, int idx,
	unsigned int *hwriq, unsigned int *type);

int of_irq_parse_max(struct device_node *dn, unsigned int *max);

struct device_node *of_irq_find_parent(struct device_node *dn);

/*
 * Find a property for a given `name` @  `dn`
 */
const void *of_get_property(const struct device_node *dn,
	const char *name, int *lenp);

/*
 * Read an unsigned long number from cells
 */
unsigned long of_read_ulong(const unsigned int *cell, int nr_cells);

/*
 * property exists or not.
 */
static inline bool of_property_read_bool(
	const struct device_node *dn, const char *propname)
{
	return of_get_property(dn, propname, NULL) ? true : false;
}

/*
 * Read reg = <addr size> or similar cell
 * idx is the index of the <addr size> pair
 */
int of_read_property_addr_size(struct device_node *dn, const char *name,
	int idx, unsigned long *addr, size_t *size);

static inline int of_parse_io_resource(struct device_node *dn,
	int idx, unsigned long *addr, size_t *size)
{
	return of_read_property_addr_size(dn, "reg", idx, addr, size);
}

static inline void *of_iomap(struct device_node *dn, int idx)
{
	int ret = -1;
	size_t size = 0;
	unsigned long addr = 0;

	ret = of_read_property_addr_size(dn, "reg", idx, &addr, &size);
	if (ret == 0)
		return iomap(addr, size);

	return NULL;
}

int of_name_equal(struct device_node *dn, const char *name);
int of_compatible_equal(struct device_node *dn, const char *compat);

static inline struct device_node *of_list_compatible_child_node(
	struct device_node *parent, struct list_head *from, const char *compat)
{
	struct device_node *dn = NULL;

	list_for_each_entry(dn, from, node) {
		if (&dn->node == &parent->child)
			break;
		if (of_compatible_equal(dn, compat))
			return dn;
	}

	return NULL;
}

static inline struct device_node *of_list_matching_child_node(
	struct device_node *parent, struct list_head *from,
	const struct of_device_id *matches)
{
	struct device_node *dn = NULL;

	list_for_each_entry(dn, from, node) {
		if (&dn->node == &parent->child)
			break;
		if (of_compatible_equal(dn, matches->compat) &&
			of_name_equal(dn, matches->name))
			return dn;
	}

	return NULL;
}

#define for_each_node_by_name(dn, name) \
	for (dn = of_find_node_by_name(NULL, name); dn; \
	     dn = of_find_node_by_name(dn, name))

#define for_each_compatible_node(dn, compat) \
	for (dn = of_find_compatible_node(NULL, compat); dn; \
	     dn = of_find_compatible_node(dn, compat))

#define for_each_matching_node(dn, matches) \
	for (dn = of_find_matching_node(NULL, matches); dn; \
	     dn = of_find_matching_node(dn, matches))

#define for_each_child_of_node(parent, dn) \
	list_for_each_entry(dn, &(parent)->child, node)

#define for_each_compatible_child_of_node(parent, dn, compat) \
	for (dn = of_list_compatible_child_node(parent, &(parent)->child, compat); \
		dn; dn = of_list_compatible_child_node(parent, &(dn)->node, compat))

#define for_each_matching_child_of_node(parent, dn, matches) \
	for (dn = of_list_matching_child_node(parent, &(parent)->child, matches); \
		dn; dn = of_list_matching_child_node(parent, &(dn)->node, matches))

#define for_each_matching_addr_size(compat, name, addr, size) \
	for (struct {int id; struct device_node *dn; int ret; } s = {0, \
		of_find_compatible_node(NULL, compat), of_read_property_addr_size( \
		s.dn, name, 0, &(addr), &(size))}; s.ret == 0; s.id++, \
		s.ret = of_read_property_addr_size(s.dn, name, s.id, &(addr), &(size)))

/*
 * for early init
 * Read reg = <addr size> or similar cell by offset instead of node
 * idx is the index of the <addr size> pair, start with 0
 */
int of_fdt_early_init(void);
int of_read_property_addr_size_by_offset(int offset,
	const char *name, int idx, unsigned long *addr, size_t *size);
int of_node_offset_by_compatible(int offset, const char *compat);

#define of_for_each_matching_addr_size(compat, name, addr, size) \
	for (struct {int id; int offset; int ret; } s = {0, of_node_offset_by_compatible(0, compat), \
		of_read_property_addr_size_by_offset(s.offset, name, 0, &(addr), &(size))}; \
		s.ret == 0; s.id++, s.ret = of_read_property_addr_size_by_offset(s.offset, \
		name, s.id, &(addr), &(size)))
/*
 * init of FDT
 */
int of_fdt_init(void);

#endif
