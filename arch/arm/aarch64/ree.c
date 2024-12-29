// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * init the REE's(Linux's) context
 */

#include <of.h>
#include <trace.h>
#include <percpu.h>
#include <power.h>

#include <init.h>
#include <kvma.h>

#include <ree.h>

/*
 * 2 ways for setting REE ctx
 * 1. set to DTS "ree-ctx" content (CPU0 only)
 * 2. set to REE kernel entry (CPU0 w/o ree-ctx, or secondary CPUs)
 */
void setup_ree(void)
{
	unsigned long ree_entry = 0;
	unsigned long ree_dtb = 0;
	struct device_node *dn = NULL;
	struct percpu *pc = thiscpu;
	struct thread_ctx_el3 *ctx = pc->rctx;
	unsigned long dts_ctx = 0;
	static bool _ctxinit;

	if (_ctxinit == false) {
		_ctxinit = true;
/* check if the DTS have REE context pointer, use it firstly if prepsent */
		dn = of_find_compatible_node(NULL, "memory");
		of_read_property_addr_size(dn, "ree-ctx", 0, &dts_ctx, NULL);
		if (dts_ctx != 0) {
			void *va = phys_to_virt(dts_ctx);

			memcpy(ctx, va, sizeof(*ctx));

			IMSG("primary ree-ctx @%lx\n", dts_ctx);
		} else {
/* linux kernel entry and DTB for primary CPU startup */
			of_read_property_addr_size(dn, "ree-addr", 0, &ree_entry, NULL);
			of_read_property_addr_size(dn, "ree-dtb", 0, &ree_dtb, NULL);

			ctx->pc = ree_entry;
			ctx->spsr = SPSR_MODE_EL2H | SPSR_DAIF_MASK;
			ctx->r[0] = ree_dtb;

			IMSG("primary entry@%lx, dtb@%lx\n", ree_entry, ree_dtb);
		}
	} else {
/* linux kernel entry for secondary CPUs startup */
#if CONFIG_NR_CPUS > 1
		ctx->pc = secondary_entry;
		ctx->spsr = SPSR_MODE_EL2H | SPSR_DAIF_MASK;

		IMSG("secondary entry@%lx\n", secondary_entry);
#endif
	}
}
