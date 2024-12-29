// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * init the REE's(Linux's) context
 */

#include <of.h>
#include <kthread.h>
#include <device.h>
#include <percpu.h>
#include <delay.h>
#include <trace.h>
#include <timer.h>

#include <power.h>
#include <ree.h>

#define REE_SPSR	(SVC_MODE | IRQ_MASK | ASYNC_ABT_MASK)

/*
 * 2 ways for setting REE ctx
 * 1. set to DTS "ree-ctx" content (CPU0 only)
 * 2. set to REE kernel entry (CPU0 w/o ree-ctx, or secondary CPUs)
 */
void setup_ree(void)
{
	struct percpu *pc = thiscpu;
	unsigned long ree_entry = 0;
	unsigned long ree_dtb = 0;
	struct device_node *dn = NULL;
	unsigned long dts_ctx = 0;
	struct thread_ctx ctx = {0};
	struct percpu_ctx rctx = {0};

/* check if the DTS have REE context pointer, use it firstly if prepsent */
	if (pc->id == 0) {
		dn = of_find_compatible_node(NULL, "memory");
		of_read_property_addr_size(dn, "ree-ctx", 0, &dts_ctx, NULL);
		if (dts_ctx != 0) {
			void *va = phys_to_virt(dts_ctx);

			memcpy(&ctx, va, sizeof(ctx)); /* thread_ctx */
			memcpy(&rctx, va + sizeof(ctx), sizeof(rctx)); /* perpcu_ctx */

			IMSG("primary ree-ctx @%lx\n", dts_ctx);
		} else {
/* linux kernel entry and DTB for primary CPU startup */
			of_read_property_addr_size(dn, "ree-addr", 0, &ree_entry, NULL);
			of_read_property_addr_size(dn, "ree-dtb", 0, &ree_dtb, NULL);

			ctx.pc = ree_entry;
			ctx.spsr = REE_SPSR;
			ctx.r[2] = ree_dtb;

			IMSG("primary entry@%lx, dtb@%lx\n", ree_entry, ree_dtb);
		}
	} else {
/* linux kernel entry for secondary CPUs startup */
#if CONFIG_NR_CPUS > 1
		ctx.pc = secondary_entry;
		ctx.spsr = REE_SPSR;

		IMSG("secondary entry@%lx\n", secondary_entry);
#endif
	}

#ifdef CONFIG_REE_THREAD

	memcpy((void *)&pc->rctx, &rctx, sizeof(rctx)); /* perpcu_ctx */
	sched_create_ree_thread(&ctx); /* thread_ctx */

#else

	/* thread_ctx_el3 = thread_ctx + percpu_ctx */
	memcpy(&pc->rctx, &ctx, sizeof(ctx)); /* thread_ctx */
	memcpy((void *)&pc->rctx + sizeof(ctx), &rctx, sizeof(rctx)); /* perpcu_ctx */

#endif
}
