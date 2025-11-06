// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Handles the platform related configurations
 */

#include <io.h>
#include <of.h>
#include <str.h>
#include <kmap.h>
#include <unistd.h>
#include <trace.h>

static void platform_pinctrl(void)
{
	int ret = 0;
	int i = 0;
	int val = 0;
	struct pinctrl_cell {
		int reg_off;
		int bit_off;
		int bit_len;
		int val;
	} cells[20];

	struct device_node *node = NULL;
	void *base = NULL;

	node = of_find_compatible_node(NULL, "module,pinctrl");
	if (!node) {
		IMSG("no pinctrls\n");
		return;
	}

	ret = of_property_count_elems_of_size(node, "pinctrls", 1);
	if (ret < 0)
		return;

	if ((unsigned int)ret > sizeof(cells)) {
		EMSG("pinctrls array size excess\n");
		return;
	}

	if (of_property_read_s32_array(node, "pinctrls", (int *)cells, ret) < 0)
		return;

	base = of_iomap(node, 0);
	if (base == NULL) {
		IMSG("no pinctrls\n");
		return;
	}

	for (i = 0; i < ret/(int)sizeof(struct pinctrl_cell); i++) {
		val = ioread32(base + cells[i].reg_off);
		val &= ~(((1 << cells[i].bit_len) - 1) << cells[i].bit_off);
		val |= (cells[i].val & ((1 << cells[i].bit_len) - 1))
				<< cells[i].bit_off;
		iowrite32(val, base + cells[i].reg_off);
	}

	iounmap(base);
}

static int platform_resume(void *data)
{
	platform_pinctrl();
	return 0;
}
DECLARE_STR_ROOT(plat, NULL, platform_resume, NULL);

static void __init platform_init(void)
{
	platform_pinctrl();
}
EARLY_INIT_ROOT(platform_init);
