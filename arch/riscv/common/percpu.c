// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Define the per-cpu structs
 */

#include <of.h>
#include <mmu.h>
#include <device.h>
#include <trace.h>
#include <tevent.h>
#include <thread.h>

#include <percpu.h>

unsigned long common_stack[CONFIG_NR_CPUS][STACK_SIZE/sizeof(long)]
	__section(".bss") __aligned(64) = {0};

struct percpu percpu_dt[CONFIG_NR_CPUS]
	__section(".bss") __aligned(64) = {0};

int __init cpu_data_init(void)
{
	int ret = -1, i = 0, start = 0, cnt = 0;
/* +1 for E-Core, e.g. sifive_u S-mode */
	unsigned int hartid_array[CONFIG_NR_CPUS * 8] = {0};

	if (IS_ENABLED(CONFIG_RISCV_S_MODE))
		start = __ctz(supervisor_bmap());

	ret = __of_property_read_u32_array(
			of_find_compatible_node(NULL, "riscv,cpu"),
			"cpus", hartid_array, CONFIG_NR_CPUS + start);
	if (ret < 0)
		return ret;

	cnt = min(CONFIG_NR_CPUS, ret - start);

	for (i = 0; i < cnt; i++) {
		percpu_dt[i].id = i;
		percpu_dt[i].hartid = hartid_array[start++];
		percpu_dt[i].stack = &common_stack[i + 1];
		cpu_affinity_set(cpus_possible, i);
	}

	return 0;
}

void percpu_info(void)
{
	char isastr[128];
	int i = 0, pos = 0, xlen = 0;
	struct percpu *pc = thiscpu;
	static const char isa_order[] = "iemafdqclbjtpvnhkorwxyzg";
	unsigned long isa = 0;

	isa = IS_ENABLED(CONFIG_RISCV_S_MODE) ? __misa : read_csr(misa);

	if (isa != 0) {
		xlen = isa >> (BITS_PER_LONG - 2);
		pos = snprintf(isastr, sizeof(isastr), "rv%d", 16u << xlen);
		for (i = 0; i < ARRAY_SIZE(isa_order); i++) {
			if (isa & (1ul << (isa_order[i] - 'a')))
				isastr[pos++] = isa_order[i];
		}
		isastr[pos] = 0;
		IMSG("cpu%d @ hart%ld - %s S:%d U:%d\n", pc->id,
			pc->hartid, isastr, isa & (1 << 18) ? 1 : 0,
			isa & (1 << 20) ? 1 : 0);
	} else {
		IMSG("cpu%d @ hart%ld\n", pc->id, pc->hartid);
	}
}
