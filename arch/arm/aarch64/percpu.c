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
 * for Interrupt/Exceptions
 */
unsigned long common_stack[CONFIG_NR_CPUS][STACK_SIZE/sizeof(long)]
	__section(".bss") __aligned(64) = {{0}};

int __init cpu_data_init(void)
{
	int ret = -1, i = 0;
	unsigned int mpid_array[CONFIG_NR_CPUS] = {0};

	ret = __of_property_read_u32_array(
			of_find_compatible_node(NULL, "arm,cpu"),
			"cpus", mpid_array, CONFIG_NR_CPUS);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		percpu_dt[i].id = i;
		percpu_dt[i].mpid = mpid_array[i];
		percpu_dt[i].stack = &common_stack[i + 1];
		cpu_affinity_set(cpus_possible, i);
	}

	return 0;
}

struct midr_struct {
	unsigned long minor: 4;
	unsigned long partnum: 12;
	unsigned long arch: 4;
	unsigned long major: 4;
	unsigned long impl: 8;
	unsigned long resved: 32;
};

struct midr_part {
	short partnum;
	const char *partstr;
};

#define MIDR_ARM_IMPL (0x41)
#define MIDR_ARM_ARCH (0xF)

#define MIDR_ARM_PART_CORTEX_A53	0xD03
#define MIDR_ARM_PART_CORTEX_A35	0xD04
#define MIDR_ARM_PART_CORTEX_A55	0xD05
#define MIDR_ARM_PART_CORTEX_A65	0xD06 /* SMT */
#define MIDR_ARM_PART_CORTEX_A57	0xD07
#define MIDR_ARM_PART_CORTEX_A72	0xD08
#define MIDR_ARM_PART_CORTEX_A73	0xD09
#define MIDR_ARM_PART_CORTEX_A75	0xD0A
#define MIDR_ARM_PART_CORTEX_A76	0xD0B
#define MIDR_ARM_PART_NEOVERSE_N1	0xD0C
#define MIDR_ARM_PART_CORTEX_A77	0xD0D
#define MIDR_ARM_PART_NEOVERSE_V1	0xD40
#define MIDR_ARM_PART_CORTEX_A78	0xD41
#define MIDR_ARM_PART_CORTEX_A65AE	0xD43 /* SMT */
#define MIDR_ARM_PART_CORTEX_X1		0xD44
#define MIDR_ARM_PART_CORTEX_A510	0xD46 /* armv9 */
#define MIDR_ARM_PART_CORTEX_A710	0xD47 /* armv9 */
#define MIDR_ARM_PART_CORTEX_X2		0xD48
#define MIDR_ARM_PART_NEOVERSE_N2	0xD49 /* armv9 */
#define MIDR_ARM_PART_NEOVERSE_E1	0xD4A /* SMT */
#define MIDR_ARM_PART_CORTEX_A78C	0xD4B
#define MIDR_ARM_PART_CORTEX_X3		0xD4E /* armv9 */
#define MIDR_ARM_PART_NEOVERSE_V2	0xD4F /* armv9 */
#define MIDR_ARM_PART_CORTEX_X4		0xD82 /* armv9 */

static const struct midr_part arm_parts[] = {
	{MIDR_ARM_PART_CORTEX_A53,   "Cortex-A53"},
	{MIDR_ARM_PART_CORTEX_A35,   "Cortex-A35"},
	{MIDR_ARM_PART_CORTEX_A55,   "Cortex-A55"},
	{MIDR_ARM_PART_CORTEX_A65,   "Cortex-A65"},
	{MIDR_ARM_PART_CORTEX_A57,   "Cortex-A57"},
	{MIDR_ARM_PART_CORTEX_A72,   "Cortex-A72"},
	{MIDR_ARM_PART_CORTEX_A73,   "Cortex-A73"},
	{MIDR_ARM_PART_CORTEX_A75,   "Cortex-A75"},
	{MIDR_ARM_PART_NEOVERSE_N1,  "Neoverse-N1"},
	{MIDR_ARM_PART_CORTEX_A76,   "Cortex-A76"},
	{MIDR_ARM_PART_CORTEX_A77,   "Cortex-A77"},
	{MIDR_ARM_PART_NEOVERSE_V1,  "Neoverse-V1"},
	{MIDR_ARM_PART_CORTEX_A78,   "Cortex-A78"},
	{MIDR_ARM_PART_CORTEX_A65AE, "Cortex-A65AE"},
	{MIDR_ARM_PART_CORTEX_X1,    "Cortex-X1"},
	{MIDR_ARM_PART_CORTEX_A510,  "Cortex-A510"},
	{MIDR_ARM_PART_CORTEX_A710,  "Cortex-A710"},
	{MIDR_ARM_PART_CORTEX_X2,    "Cortex-X2"},
	{MIDR_ARM_PART_NEOVERSE_N2,  "Neoverse-N2"},
	{MIDR_ARM_PART_NEOVERSE_E1,  "Neoverse-E1"},
	{MIDR_ARM_PART_CORTEX_A78C,  "Cortex-A78C"},
	{MIDR_ARM_PART_CORTEX_X3,    "Cortex-X3"},
	{MIDR_ARM_PART_NEOVERSE_V2,  "Neoverse-V2"},
	{MIDR_ARM_PART_CORTEX_X4,    "Cortex-X4"},
};

void percpu_info(void)
{
	int i = 0;
	struct midr_struct m = {0};
	const char *partstr = NULL;
	unsigned long mpidr = 0;

	BUILD_ERROR_ON(sizeof(struct thread_ctx_el3) > 1024);

	asm volatile("mrs %0, midr_el1\n"
				 : "=r" (m)
				 :
				 : "memory", "cc");

	mpidr = read_system_reg(mpidr_el1);

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
	else {
		IMSG("Processor %s r%dp%d\n", partstr, m.major, m.minor);
		IMSG("Processor %lx SecurityExtn %d\n", mpidr, cpu_has_security_extn());
	}
}
