// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>
 * TLB related functionalities for RISCV based SoCs
 */

#include <ipi.h>
#include <init.h>
#include <errno.h>
#include <trace.h>
#include <delay.h>
#include <interrupt.h>
#include <sections.h>
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

/*
 * Send IPI to all online CPUs except the current one,
 * with retry when target ring buffers are full.
 *
 * Uses ipi_try_call() for non-blocking attempts,
 * avoiding the 200us busy-wait of ipi_call() per CPU.
 *
 * First pass runs with IRQs disabled for accurate
 * identification of the current CPU. If any IPI fails
 * (ring full), poke targets to drain their rings and
 * retry with IRQs enabled.
 */
static void ipi_call_retry(void *func, void *data, size_t size)
{
	int cpu = 0, currcpu = 0;
	unsigned long flags = 0;
	unsigned long pending_cpus = 0;
	unsigned long online_cpus = 0;

	local_irq_save(flags);

	currcpu = percpu_id();
	for_each_online_cpu(cpu) {
		if (currcpu != cpu) {
			if (ipi_try_call(func, cpu, data, size) != 0)
				pending_cpus |= 1UL << cpu;
		}
	}

	local_irq_restore(flags);

	if (!pending_cpus)
		return;

	/*
	 * Poke failed CPUs to drain their rings.
	 * The softint triggers ipi_isr() on each target.
	 */
	for_each_online_cpu(cpu) {
		if (pending_cpus & (1UL << cpu))
			softint_raise(SOFTINT_IPI, cpu);
	}

	/*
	 * Retry with IRQs enabled, allowing target CPUs
	 * to process the softint and drain their rings,
	 * and allowing this CPU to service incoming IPIs.
	 */
	while (pending_cpus) {
		online_cpus = 0;
		for_each_online_cpu(cpu) {
			online_cpus |= 1UL << cpu;
			if ((pending_cpus & (1UL << cpu)) &&
				ipi_try_call(func, cpu, data, size) == 0)
				pending_cpus &= ~(1UL << cpu);
		}
		pending_cpus &= online_cpus;
	}
}

void flush_tlb_pte(unsigned long va, unsigned long asid)
{
	struct tlb_info info;

	local_flush_tlb_pte(va, asid);

	info.va = va;
	info.asid = asid;

	ipi_call_retry(__ipi_flush_tlb, &info, sizeof(info));
}

void flush_tlb_asid(unsigned long asid)
{
	struct tlb_info info;

	info.va = 0;
	info.asid = asid;

	local_flush_tlb_asid(asid);

	ipi_call_retry(__ipi_flush_tlb, &info, sizeof(info));
}

void flush_tlb_all(void)
{
	local_flush_tlb_all();

	ipi_call_retry(__ipi_flush_tlb, NULL, 0);
}

void flush_icache_all(void)
{
	local_flush_icache_all();

	ipi_call_retry(__ipi_flush_icache, NULL, 0);
}

#endif
