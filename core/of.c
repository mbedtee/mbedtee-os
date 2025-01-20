// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Device Tree - Open Firmware Implementation
 */

#include <of.h>
#include <libfdt.h>
#include <driver.h>
#include <kmalloc.h>
#include <strmisc.h>

#include <generated/autoconf.h>

static const void *__dtb;
static struct device_node *__root_dn;

static struct device_node *of_alloc_root(void)
{
	struct device_node *dn = NULL;

	dn = kzalloc(sizeof(struct device_node));
	if (dn == NULL)
		return NULL;

	dn->id.name = "/";

	INIT_LIST_HEAD(&dn->node);
	INIT_LIST_HEAD(&dn->child);

	return dn;
}

static struct device_node *of_alloc_node(
	struct device_node *parent, int offset)
{
	struct device_node *dn = NULL;

	dn = kzalloc(sizeof(struct device_node));
	if (dn == NULL)
		return NULL;

	dn->offset = offset;
	dn->id.name = fdt_get_name(__dtb, offset, NULL);
	dn->id.compat = fdt_getprop(__dtb, offset,
					"compatible", NULL);
	dn->parent = parent;

	dn->phandle = fdt_get_phandle(__dtb, offset);

	while (parent->next)
		parent = parent->next;
	parent->next = dn;

	INIT_LIST_HEAD(&dn->node);
	INIT_LIST_HEAD(&dn->child);

	parent = dn;
	fdt_for_each_subnode(offset, __dtb, parent->offset) {
		dn = of_alloc_node(parent, offset);
		list_add_tail(&dn->node, &parent->child);
	}

	return parent;
}

static void of_populate_nodes(void)
{
	int offset = 0;
	struct device_node *dn = NULL;

	__root_dn = of_alloc_root();

	/* from root */
	fdt_for_each_subnode(offset, __dtb, 0) {
		dn = of_alloc_node(__root_dn, offset);
		list_add_tail(&dn->node, &__root_dn->child);
	}
}

int of_fdt_init(void)
{
	void *local_dtb = NULL;

#ifndef CONFIG_EMBEDDED_DTB
	void *dtb_addr = phys_to_virt(CONFIG_DTB_ADDR);
	size_t dtb_size = fdt_totalsize(dtb_addr);

	local_dtb = kmalloc(dtb_size);
	if (!local_dtb)
		return -ENOMEM;

	memcpy(local_dtb, dtb_addr, dtb_size);
#else
	local_dtb = (void *)__dtb_start();
#endif

	if (fdt_check_header(local_dtb))
		return -EINVAL;

	__dtb = local_dtb;

	of_populate_nodes();

	return 0;
}

int of_fdt_early_init(void)
{
	void *local_dtb = NULL;

#ifndef CONFIG_EMBEDDED_DTB
	local_dtb = phys_to_virt(CONFIG_DTB_ADDR);
#else
	local_dtb = (void *)__dtb_start();
#endif

	if (fdt_check_header(local_dtb))
		return -EINVAL;

	__dtb = local_dtb;

	return 0;
}

static int of_property_read_u32_array_by_offset(int offset,
	const char *propname, unsigned int *out_values, int sz)
{
	int len, proplen = 0;
	const unsigned int *val = NULL;

	val = fdt_getprop(__dtb, offset, propname, &proplen);

	if ((!proplen) || (!val))
		return -ENODATA;

	len = (proplen > (sz * sizeof(unsigned int))) ?
		(sz * sizeof(unsigned int)) : proplen;

	while (len && out_values) {
		*out_values++ = fdt32_to_cpu(*val++);
		len -= sizeof(unsigned int);
	}

	return 0;
}

int of_read_property_addr_size_by_offset(int offset,
	const char *name, int idx, unsigned long *addr, size_t *size)
{
	int plen = 0;
	unsigned int naddr = 0, nsize = 0;
	const unsigned int *range = NULL;

	of_property_read_u32_array_by_offset(0, "#address-cells", &naddr, 1);
	of_property_read_u32_array_by_offset(0, "#size-cells", &nsize, 1);

	if (naddr == 0 || nsize == 0)
		return -ENODATA;

	range = fdt_getprop(__dtb, offset, name, &plen);
	if (range == NULL)
		return -ENODATA;

	if (plen/sizeof(int) <= (size_t)(naddr + nsize) * idx)
		return -ENODATA;

	if (addr)
		*addr = of_read_ulong(range + (naddr + nsize) * idx, naddr);
	if (size)
		*size = of_read_ulong(range + (naddr + nsize) * idx + naddr, nsize);

	return 0;
}

int of_node_offset_by_compatible(int offset, const char *compat)
{
	return fdt_node_offset_by_compatible(__dtb, offset, compat);
}

int of_name_equal(struct device_node *dn, const char *name)
{
	char *s1 = strchrnul(dn->id.name, '@');
	char *s2 = strchrnul(name, '@');

	if (*s2)
		return (strcasecmp(dn->id.name, name) == 0);

	return (s1 - dn->id.name == s2 - name &&
		(strncasecmp(dn->id.name, name, s2 - name) == 0));
}

int of_compatible_equal(struct device_node *dn, const char *compat)
{
	return (dn->id.compat && (strcasecmp(dn->id.compat, compat) == 0));
}

struct device_node *of_find_node_by_name(
	struct device_node *from,
	const char *name)
{
	struct device_node *dn = NULL;

	if (name == NULL)
		return NULL;

	dn = (from == NULL) ? __root_dn : from;

	while ((dn = dn->next) != NULL) {
		if (of_name_equal(dn, name))
			return dn;
	}

	return NULL;
}

struct device_node *of_find_node_by_phandle(unsigned int phandle)
{
	struct device_node *dn = __root_dn;

	if (phandle == 0)
		return NULL;

	while ((dn = dn->next) != NULL) {
		if (phandle == dn->phandle)
			return dn;
	}

	return NULL;
}

struct device_node *of_find_compatible_node(
	struct device_node *from,
	const char *compat)
{
	struct device_node *dn = NULL;

	if (compat == NULL)
		return NULL;

	dn = (from == NULL) ? __root_dn : from;

	while ((dn = dn->next) != NULL) {
		if (of_compatible_equal(dn, compat))
			return dn;
	}

	return NULL;
}

struct device_node *of_find_matching_node(
	struct device_node *from,
	const struct of_device_id *matches)
{
	struct device_node *dn = NULL;

	if (matches == NULL)
		return NULL;

	dn = (from == NULL) ? __root_dn : from;

	while ((dn = dn->next) != NULL) {
		if (of_compatible_equal(dn, matches->compat) &&
			of_name_equal(dn, matches->name))
			return dn;
	}

	return NULL;
}

int of_property_read_u32_array(struct device_node *dn,
	const char *propname, unsigned int *out_values, int cnt)
{
	int len, proplen = 0;
	const unsigned int *val = NULL;

	val = fdt_getprop(__dtb, dn ? dn->offset : -1, propname, &proplen);

	if ((!proplen) || (!val))
		return -ENODATA;

	len = cnt * sizeof(unsigned int);

	if (proplen < len)
		return -EOVERFLOW;

	while (len && out_values) {
		*out_values++ = fdt32_to_cpu(*val++);
		len -= sizeof(unsigned int);
	}

	return 0;
}

int of_property_read_u32(struct device_node *dn,
	const char *propname, unsigned int *out_value)
{
	return of_property_read_u32_array(dn, propname, out_value, 1);
}

int of_property_read_s32_array(struct device_node *dn,
	const char *propname, int *out_values, int cnt)
{
	return of_property_read_u32_array(dn, propname, (unsigned int *)out_values, cnt);
}

int of_property_read_s32(struct device_node *dn,
	const char *propname, int *out_value)
{
	return of_property_read_u32(dn, propname, (unsigned int *)out_value);
}

int of_property_count_elems_of_size(const struct device_node *dn,
	const char *propname, int elem_size)
{
	int proplen = 0;

	const int *val = fdt_getprop_namelen(__dtb,
			dn ? dn->offset : -1, propname,
			strlen(propname), &proplen);

	if ((!proplen) || (!val))
		return -ENODATA;

	return (proplen / elem_size);
}

int of_n_addr_cells(struct device_node *dn)
{
	unsigned int naddr = 1;

	do {
		if (dn->parent)
			dn = dn->parent;

		if (!of_property_read_u32(dn, "#address-cells", &naddr))
			break;
	} while (dn->parent);

	return naddr;
}

int of_n_size_cells(struct device_node *dn)
{
	unsigned int nsize = 1;

	do {
		if (dn->parent)
			dn = dn->parent;

		if (!of_property_read_u32(dn, "#size-cells", &nsize))
			break;
	} while (dn->parent);

	return nsize;
}

const void *of_get_property(const struct device_node *dn,
	const char *name, int *lenp)
{
	return fdt_getprop_namelen(__dtb, dn->offset,
			name, strlen(name), lenp);
}

unsigned long of_read_ulong(const unsigned int *cells, int nr_cells)
{
	unsigned long long r = 0;

	for (; nr_cells--; cells++)
		r = (r << 32) | fdt32_to_cpu(*cells);

	return r;
}

int of_read_property_addr_size(struct device_node *dn, const char *name,
	int idx, unsigned long *addr, size_t *size)
{
	int naddr = 0, nsize = 0, plen = 0;
	const unsigned int *range = NULL;

	naddr = of_n_addr_cells(dn);
	nsize = of_n_size_cells(dn);

	range = of_get_property(dn, name, &plen);
	if (range == NULL)
		return -ENODATA;

	if (plen/sizeof(int) <= (size_t)(naddr + nsize) * idx)
		return -ENODATA;

	if (addr)
		*addr = of_read_ulong(range + (naddr + nsize) * idx, naddr);
	if (size)
		*size = of_read_ulong(range + (naddr + nsize) * idx + naddr, nsize);

	return 0;
}

struct device_node *of_irq_find_parent(struct device_node *dn)
{
	unsigned int phandle = 0;

	if (of_property_read_u32(dn, "interrupt-parent", &phandle) == 0)
		return of_find_node_by_phandle(phandle);

	return NULL;
}
