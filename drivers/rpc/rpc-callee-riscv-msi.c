// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * RPC Callee (REE->TEE)
 * HW MSI (IMSIC_SGI_ID) or SW periodic polling
 */

#include <of.h>
#include <mmu.h>
#include <init.h>
#include <thread.h>
#include <timer.h>
#include <mutex.h>
#include <string.h>
#include <trace.h>
#include <cache.h>
#include <buddy.h>
#include <sleep.h>
#include <errno.h>
#include <atomic.h>
#include <tevent.h>
#include <spinlock.h>
#include <interrupt.h>
#include <intc-aplic-imsic.h>

#include <rpc_callee.h>

static SPIN_LOCK(callee_lock);
static unsigned int r2t_ring_sz;
static unsigned int r2t_ring_rd;
static struct rpc_ringbuf *r2t_ring;
#if defined(CONFIG_RPC_R2T_POLL_1MS)
static struct tevent r2t_poll_evt;
#endif

static inline unsigned int rpc_available_size(
	struct rpc_ringbuf *ring)
{
	unsigned int wr = 0;
	unsigned int rd = r2t_ring_rd;
	unsigned int shm_size = r2t_ring_sz;

	/*
	 * ring->wr may be updated by other CPUs;
	 * make sure it is visible and up to date.
	 */
	wr = smp_load_acquire(&ring->wr);

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

	r2t_ring_rd = rd;

	/* Publish consumer read pointer after all reads from ring payload. */
	smp_store_release(&ring->rd, rd);
}

static inline int rpc_pick_next(
	struct rpc_ringbuf *ring,
	unsigned long *remote)
{
	/*
	 * The REE always writes a uint64_t physical address into the r2t ring,
	 * regardless of REE pointer width, so read exactly 8 bytes here.
	 * On a 32-bit TEE the upper 32 bits are zero (phys fits in 32 bits).
	 */
	uint64_t wire_remote;

	if (rpc_available_size(ring) < sizeof(wire_remote))
		return -EAGAIN;

	rpc_ring_read(ring, &wire_remote, sizeof(wire_remote));
	*remote = (unsigned long)wire_remote;

	return 0;
}

static int rpc_callee_isr(void *data)
{
	int ret = -1, cnt = 0;
	unsigned long flags = 0;
	unsigned long remote = 0;
	struct rpc_ringbuf *ring = data;

	if (!ring || (r2t_ring_rd == smp_load_acquire(&ring->wr)))
		return 0;

	spin_lock_irqsave(&callee_lock, flags);

	while (r2t_ring_rd != smp_load_acquire(&ring->wr)) {
		ret = rpc_pick_next(ring, &remote);
		if (ret != 0)
			break;

		rpc_callee_handler(remote);

		cnt++;
	}

	spin_unlock_irqrestore(&callee_lock, flags);

	return cnt;
}

#if defined(CONFIG_RPC_R2T_POLL_1MS)
static void rpc_r2t_poll_event(struct tevent *t)
{
	/* Keep polling as a fallback when no MSI doorbell is available. */
	if (rpc_callee_isr(r2t_ring))
		tevent_start(t, &(struct timespec){0, 1000000});
	else
		tevent_start(t, &(struct timespec){0, 5000000});
}
#endif

static __init void rpc_callee_init(void)
{
	int ret = -1;
	unsigned long addr = 0;
	size_t size = 0;
	struct device_node *dn = NULL;

	dn = of_find_compatible_node(NULL, "memory");
	if (!dn)
		return;

	ret = of_read_property_addr_size(dn, "rpc-r2t-ring", 0, &addr, &size);
	if (ret != 0) {
		EMSG("error rpc-r2t-ring dts\n");
		return;
	}

	r2t_ring = phys_to_virt(addr);
	r2t_ring_sz = size - sizeof(struct rpc_ringbuf);
	r2t_ring->rd = r2t_ring->wr = r2t_ring_rd;
	r2t_ring->callee_hartid = percpu_hartid();
	r2t_ring->callee_imsic_id = IMSIC_SGI_ID;
	r2t_ring->callee_ready = true;

	softint_register(SOFTINT_RPC_CALLEE, rpc_callee_isr, r2t_ring);

#if defined(CONFIG_RPC_R2T_POLL_1MS)
	tevent_init(&r2t_poll_evt, rpc_r2t_poll_event, r2t_ring);
	tevent_start(&r2t_poll_evt, &(struct timespec){0, 5000000});
#endif

	IMSG("rpc-r2t-ring=%p size=%ld\n", r2t_ring, (long)r2t_ring_sz);
}

MODULE_INIT_CORE(rpc_callee_init);
