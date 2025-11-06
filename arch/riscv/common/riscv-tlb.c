// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * TLB related functionalities for RISCV based SoCs
 */

#include <ipi.h>
#include <init.h>
#include <errno.h>
#include <trace.h>
#include <delay.h>
#include <interrupt.h>
#include <sections.h>
#include <stdbool.h>
#include <percpu.h>
#include <power.h>

#include "riscv-tlb.h"

#if CONFIG_NR_CPUS > 1

struct tlb_info {
	unsigned long va;
	unsigned long asid;
};

static void __ipi_flush_tlb(void *data, size_t size)
{
	struct tlb_info *t = data;

	if (size == 0)
		local_flush_tlb_all();
	else if (t->va)
		local_flush_tlb_pte(t->va, t->asid);
	else if (t->asid)
		local_flush_tlb_asid(t->asid);
}

static void __ipi_flush_icache(void *data, size_t size)
{
	local_flush_icache_all();
}

void flush_tlb_pte(unsigned long va, unsigned long asid)
{
	struct tlb_info info;
	int cpu = 0, currcpu = 0;
	unsigned long flags = 0;

	local_irq_save(flags);

	info.va = va;
	info.asid = asid;

	local_flush_tlb_pte(va, asid);

	currcpu = percpu_id();
	for_each_online_cpu(cpu) {
		if (currcpu != cpu)
			ipi_call(__ipi_flush_tlb, cpu, &info, sizeof(info));
	}

	local_irq_restore(flags);
}

void flush_tlb_asid(unsigned long asid)
{
	struct tlb_info info;
	int cpu = 0, currcpu = 0;
	unsigned long flags = 0;

	local_irq_save(flags);

	info.va = 0;
	info.asid = asid;

	local_flush_tlb_asid(asid);

	currcpu = percpu_id();
	for_each_online_cpu(cpu) {
		if (currcpu != cpu)
			ipi_call(__ipi_flush_tlb, cpu, &info, sizeof(info));
	}

	local_irq_restore(flags);
}

void flush_tlb_all(void)
{
	int cpu = 0, currcpu = 0;
	unsigned long flags = 0;

	local_irq_save(flags);

	local_flush_tlb_all();

	currcpu = percpu_id();
	for_each_online_cpu(cpu) {
		if (currcpu != cpu)
			ipi_call(__ipi_flush_tlb, cpu, NULL, 0);
	}

	local_irq_restore(flags);
}

void flush_icache_all(void)
{
	int cpu = 0, currcpu = 0;
	unsigned long flags = 0;

	local_irq_save(flags);

	local_flush_icache_all();

	currcpu = percpu_id();
	for_each_online_cpu(cpu) {
		if (currcpu != cpu)
			ipi_call(__ipi_flush_icache, cpu, NULL, 0);
	}

	local_irq_restore(flags);
}

#endif
