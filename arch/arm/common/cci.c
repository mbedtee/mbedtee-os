// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * arm cci snoop/dvm enable
 */

#include <io.h>
#include <of.h>
#include <defs.h>
#include <kmap.h>
#include <kproc.h>
#include <trace.h>
#include <driver.h>
#include <interrupt.h>
#include <generated/autoconf.h>

#define CCI_SLAVE_PORT_CTRL		0x0

#define CCI_SUPPORT_SNOOP_REQ	(1 << 30)
#define CCI_SUPPORT_DVM_REQ		(1 << 31)
#define CCI_ENABLE_SNOOP_REQ	(1 << 0)
#define CCI_ENABLE_DVM_REQ		(1 << 1)

static struct device_node *ccidn;

static const struct of_device_id cci_slave_if = {
	.name = "slave-if", .compat = "arm,cci-slave-ctrl-if",
};

static int cci_enable_slave(void *base)
{
	unsigned long phys = user_virt_to_phys_pt(kpt(), base);

	if ((ioread32(base + CCI_SLAVE_PORT_CTRL) &
		(CCI_SUPPORT_SNOOP_REQ | CCI_SUPPORT_DVM_REQ)) == 0) {
		EMSG("Snoop/DVM not support @ %lx\n", phys);
		return -ENOTSUP;
	}

	IMSG("Snoop/DVM support @ %lx\n", phys);
	iowrite32(CCI_ENABLE_SNOOP_REQ | CCI_ENABLE_DVM_REQ,
			base + CCI_SLAVE_PORT_CTRL);

	return 0;
}

static int cci_enable(void *data)
{
	int ret = -1;
	struct device_node *child = NULL;
	struct device_node *dn = ccidn;
	void *base = NULL;

	IMSG("init %s\n", dn->id.compat);

	for_each_matching_child_of_node(dn, child, &cci_slave_if) {
		base = of_iomap(child, 0);
		if (base == NULL) {
			EMSG("cci dts\n");
			return -EINVAL;
		}
		ret = cci_enable_slave(base);
		iounmap(base);
	}

	return ret;
}
DECLARE_STR_ROOT(cci, NULL, cci_enable, NULL);

static int __init cci_probe(struct device *dev)
{
	ccidn = container_of(dev, struct device_node, dev);

	return cci_enable(NULL);
}

static const struct of_device_id of_cci_desc[] = {
	{.name = "cci", .compat = "arm,cci-400"},
	{.name = "cci", .compat = "arm,cci-500"},
	{},
};

static const struct device_driver of_cci = {
	.name = "arm,cci",
	.probe = cci_probe,
	.of_match_table = of_cci_desc,
};

module_root(of_cci);
