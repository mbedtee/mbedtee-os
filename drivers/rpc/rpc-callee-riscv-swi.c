// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RPC Callee (REE->TEE)
 * (triggerred by hw-ipi, similar as the functionality of ARM SMC)
 */

#include <of.h>
#include <mmu.h>
#include <thread.h>
#include <timer.h>
#include <interrupt.h>
#include <mutex.h>
#include <string.h>
#include <trace.h>
#include <cache.h>
#include <buddy.h>
#include <spinlock.h>
#include <sleep.h>
#include <driver.h>
#include <errno.h>

#include <rpc_callee.h>

static SPIN_LOCK(callee_lock);
static unsigned int r2t_ring_sz;
static unsigned int r2t_ring_rd;
static struct rpc_ringbuf *r2t_ring;

static inline unsigned int rpc_available_size(
	struct rpc_ringbuf *ring)
{
	unsigned int wr = 0;
	unsigned int rd = r2t_ring_rd;
	unsigned int shm_size = r2t_ring_sz;

	/*
	 * ring->wr is possibly updating by other CPUs,
	 * make sure the it is visible and update to date
	 */
	smp_mb();
	wr = ring->wr;

	if (wr > shm_size)
		return 0;

	if (wr >= rd)
		return wr - rd;
	else
		return shm_size + wr - rd;
}

static void rpc_ring_read(
	struct rpc_ringbuf *ring,
	void *data, unsigned int size)
{
	unsigned int remain = 0;
	unsigned int shm_size = r2t_ring_sz;
	unsigned int rd = r2t_ring_rd;

	if (rd + size <= shm_size) {
		memcpy(data, &ring->mem[rd], size);
		rd += size;
	} else {
		remain = rd + size - shm_size;
		memcpy(data, &ring->mem[rd], size - remain);
		memcpy((unsigned char *)data + size - remain,
				&ring->mem[0], remain);
		rd = remain;
	}

	ring->rd = r2t_ring_rd = rd;

	/* make sure the update to ring->rd is visible to others */
	smp_mb();
}

static inline int rpc_pick_next(
	struct rpc_ringbuf *ring,
	unsigned long *remote)
{
	if (rpc_available_size(ring) < sizeof(*remote))
		return -EAGAIN;

	rpc_ring_read(ring, remote, sizeof(*remote));

	return 0;
}

static void rpc_callee_isr(void *unused)
{
	int ret = -1;
	unsigned long retry = 0;
	struct rpc_ringbuf *ring = r2t_ring;
	unsigned long flags = 0;
	unsigned long remote = 0;

	if (!ring || (r2t_ring_rd == ring->wr))
		return;

	spin_lock_irqsave(&callee_lock, flags);

	while (r2t_ring_rd != ring->wr) {
		ret = rpc_pick_next(ring, &remote);
		if (ret != 0) {
			if (++retry == 5000) {
				IMSG("rpc retried\n");
				break;
			}
			continue;
		}

		rpc_callee_handler(remote);
	}

	spin_unlock_irqrestore(&callee_lock, flags);
}

static __init int rpc_callee_init(struct device *dev)
{
	struct device_node *dn = NULL;
	int ret = -1, naddr = 0, nsize = 0, plen = 0;
	const unsigned int *range = NULL;

	dn = container_of(dev, struct device_node, dev);
	naddr = of_n_addr_cells(dn);
	nsize = of_n_size_cells(dn);

	range = of_get_property(dn, "rpc-r2t-ring", &plen);
	if (range == NULL || (plen/sizeof(int) != naddr + nsize)) {
		EMSG("error rpc-r2t-ring dts\n");
		return ret;
	}

	r2t_ring = phys_to_virt(of_read_ulong(range, naddr));
	r2t_ring_sz = of_read_ulong(range + naddr, nsize);
	r2t_ring_sz -= sizeof(struct rpc_ringbuf);
	r2t_ring->rd = r2t_ring->wr = r2t_ring_rd;

	register_softint(SOFTINT_RPC_CALLEE, rpc_callee_isr, NULL);

	IMSG("r2t-ring=%p size=%ld\n", r2t_ring, (long)r2t_ring_sz);

	return 0;
}

static const struct of_device_id of_rpc_callee_id[] = {
	{.name = "memory", .compat = "memory"},
	{},
};

static const struct device_driver of_rpc_callee = {
	.name = "rpc-callee",
	.probe = rpc_callee_init,
	.of_match_table = of_rpc_callee_id,
};

module_core(of_rpc_callee);
