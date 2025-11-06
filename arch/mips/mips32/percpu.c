// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Define the per-cpu structs
 */

#include <mmu.h>
#include <device.h>
#include <trace.h>
#include <tevent.h>
#include <thread.h>

#include <percpu.h>

unsigned long common_stack[CONFIG_NR_CPUS][STACK_SIZE/sizeof(long)]
	__section(".bss") __aligned(64) = {{0}};

struct percpu percpu_dt[CONFIG_NR_CPUS]
	__section(".bss") __aligned(64) = {{0}};

int __init cpu_data_init(void)
{
	int i = 0;

	for (i = 0; i < CONFIG_NR_CPUS; i++) {
		percpu_dt[i].id = i;
		percpu_dt[i].stack = &common_stack[i + 1];
		cpu_affinity_set(cpus_possible, i);
	}

	return 0;
}

struct prid_struct {
	unsigned long patch_l:2;
	unsigned long minor:3;
	unsigned long major:3;
	unsigned long impl:8;
	unsigned long comp:8;
	unsigned long comp_opt:8;
};

struct prid_part {
	short partnum;
	const char *partstr;
};

#define PRID_MIPS_COMP (0x1)

#define PRID_MIPS_PART_24K   0x93
#define PRID_MIPS_PART_34K   0x95
#define PRID_MIPS_PART_24KE  0x96
#define PRID_MIPS_PART_74K   0x97
#define PRID_MIPS_PART_M14K  0x9C
#define PRID_MIPS_PART_P5600 0xA8

static const struct prid_part mips_parts[] = {
	{PRID_MIPS_PART_24K,   "MIPS-24K"},
	{PRID_MIPS_PART_24KE,  "MIPS-24KE"},
	{PRID_MIPS_PART_34K,   "MIPS-34K"},
	{PRID_MIPS_PART_74K,   "MIPS-74K"},
	{PRID_MIPS_PART_M14K,  "MIPS-M14K"},
	{PRID_MIPS_PART_P5600, "MIPS-P5600"},
};

void percpu_info(void)
{
	int i = 0;
	struct prid_struct m = {0};
	const char *partstr = NULL;
	long prid = read_cp0_register(C0_PRID);

	memcpy((struct prid_struct *)&m, &prid, sizeof(m));

	assert(m.comp == PRID_MIPS_COMP);

	for (i = 0; i < ARRAY_SIZE(mips_parts); i++) {
		if (m.impl == mips_parts[i].partnum) {
			partstr = mips_parts[i].partstr;
			break;
		}
	}

	if (partstr == NULL)
		EMSG("unknown partnum 0x%x\n", m.impl);
	else
		IMSG("Processor %s r%d.%dp%d\n", partstr, m.major, m.minor, m.patch_l);
}
