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

/*
 * At least aligned to CACHE_LINE size (64 bytes),
 * otherwise the CACHE_LINE uses by 2 CPU will be corrupted
 * during the MMU/SMP unready stage.
 */
struct percpu percpu_dt[CONFIG_NR_CPUS]
	__section(".bss") __aligned(64) = {{0}};

/*
 * for SVC/SYS/IRQ/UND/ABT modes
 */
unsigned long common_stack[CONFIG_NR_CPUS][STACK_SIZE/sizeof(long)]
	__section(".bss") __aligned(64) = {{0}};

int __init cpu_data_init(void)
{
	int ret = -1, i = 0, mpid_array[CONFIG_NR_CPUS] = {0};

	ret = of_property_read_s32_array(
			of_find_compatible_node(NULL, "arm,cpu"),
			"cpus", mpid_array, CONFIG_NR_CPUS);
	if (ret != 0)
		return ret;

	for (i = 0; i < CONFIG_NR_CPUS; i++) {
		percpu_dt[i].id = i;
		percpu_dt[i].mpid = mpid_array[i];
		percpu_dt[i].stack = &common_stack[i + 1];
	}

	return 0;
}

struct midr_struct {
	unsigned long minor:4;
	unsigned long partnum:12;
	unsigned long arch:4;
	unsigned long major:4;
	unsigned long impl:8;
};

struct midr_part {
	short partnum;
	const char *partstr;
};

#define MIDR_ARM_IMPL (0x41)
#define MIDR_ARM_ARCH (0xF)

#define MIDR_ARM_PART_CORTEX_A5		0xC05
#define MIDR_ARM_PART_CORTEX_A7		0xC07
#define MIDR_ARM_PART_CORTEX_A8		0xC08
#define MIDR_ARM_PART_CORTEX_A9		0xC09
#define MIDR_ARM_PART_CORTEX_A12	0xC0D
#define MIDR_ARM_PART_CORTEX_A17	0xC0E
#define MIDR_ARM_PART_CORTEX_A15	0xC0F

static const struct midr_part arm_parts[] = {
	{MIDR_ARM_PART_CORTEX_A5,  "Cortex-A5"},
	{MIDR_ARM_PART_CORTEX_A7,  "Cortex-A7"},
	{MIDR_ARM_PART_CORTEX_A8,  "Cortex-A8"},
	{MIDR_ARM_PART_CORTEX_A9,  "Cortex-A9"},
	{MIDR_ARM_PART_CORTEX_A12, "Cortex-A12"},
	{MIDR_ARM_PART_CORTEX_A17, "Cortex-A17"},
	{MIDR_ARM_PART_CORTEX_A15, "Cortex-A15"},
};

void percpu_info(void)
{
	int i = 0;
	struct midr_struct m = {0};
	const char *partstr = NULL;

	asm volatile("mrc p15, 0, %0, c0, c0, 0\n"
				 : "=r" (m)
				 :
				 : "memory", "cc");

	assert(m.impl == MIDR_ARM_IMPL);
	assert(m.arch == MIDR_ARM_ARCH);

	for (i = 0; i < ARRAY_SIZE(arm_parts); i++) {
		if (m.partnum == arm_parts[i].partnum) {
			partstr = arm_parts[i].partstr;
			break;
		}
	}

	if (partstr == NULL)
		EMSG("unknown partnum 0x%x\n", m.partnum);
	else
		IMSG("Processor %s r%dp%d\n", partstr, m.major, m.minor);
}
