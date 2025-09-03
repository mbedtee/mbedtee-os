// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * RPC Caller (TEE->REE)
 */

#include <of.h>
#include <mmu.h>
#include <init.h>
#include <timer.h>
#include <mutex.h>
#include <errno.h>
#include <string.h>
#include <trace.h>
#include <cache.h>
#include <delay.h>
#include <buddy.h>
#include <sleep.h>
#include <thread.h>
#include <kmalloc.h>
#include <spinlock.h>
#include <interrupt.h>
#include <atomic.h>
#if IS_ENABLED(CONFIG_RISCV_IMSIC)
#include <intc-aplic-imsic.h>
#endif

#include <rpc.h>

#define RPC_SYNC_WAIT_SLICE_US	(20 * 1000)

static SPIN_LOCK(rpc_lock);
static SPIN_LOCK(rpcshm_lock);
static unsigned int t2r_ring_sz;
static unsigned int t2r_ring_wr;
static struct rpc_ringbuf *t2r_ring;
static struct buddy_pool t2r_shm = {0};

#if defined(CONFIG_ARM)
static unsigned int rpc_t2r_spi;
extern void gic_pend_spi(unsigned int spi);
#endif

/*
 * Notify the REE callee that new RPC data is available.
 *
 * IMSIC: deliver the doorbell directly to callee_hartid via imsic_raise.
 *
 * ARM with SPI: trigger the T2R SPI; TEE's GIC driver broadcasts it to
 * all alive CPUs via GICv2 ITARGETS=0xFF or GICv3 IROUTER.IRM=1.
 * TrustZone shares physical CPUs, so no cpumask from Linux is needed.
 *
 * RISCV non-IMSIC: no T2R doorbell available (SSWI/CLINT is fully used
 * by Linux IPI and cannot be shared). Only IMSIC MSI is supported.
 */
static inline void rpc_notify_callee(void)
{
#if defined(CONFIG_RISCV_IMSIC)
	uint32_t imsic_id = smp_load_acquire(&t2r_ring->callee_imsic_id);

	if (imsic_id)
		imsic_raise(smp_load_acquire(&t2r_ring->callee_hartid), imsic_id);
#endif

#if defined(CONFIG_ARM)
	if (rpc_t2r_spi)
		gic_pend_spi(rpc_t2r_spi);
#endif
}

#define IS_RPC_SHM(x) (((x) >= t2r_shm.start) && \
	((x) < t2r_shm.start + (1ul << t2r_shm.order)))

void *rpc_shm_alloc(size_t size)
{
	void *shm = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&rpcshm_lock, flags);

	shm = buddy_alloc(&t2r_shm, size);

	spin_unlock_irqrestore(&rpcshm_lock, flags);

	if (shm)
		memset(shm, 0, roundup2pow(size));

	if (!shm)
		EMSG("rpc shm not enough - %lx\n", (long)size);

	return shm;
}

void rpc_shm_free(void *addr)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&rpcshm_lock, flags);

	buddy_free(&t2r_shm, addr);

	spin_unlock_irqrestore(&rpcshm_lock, flags);
}

/*
 * Return whether the callee is ready.
 */
int rpc_test_callee(void)
{
	int ready = 0;

	if (t2r_ring)
		ready = smp_load_acquire(&t2r_ring->callee_ready);

	return ready;
}

/*
 * Check if the remaining ring buffer is
 * large enough for the current call.
 */
static int rpc_ring_enough(unsigned int size)
{
	unsigned int rd = 0;
	unsigned int remain = 0, ringsz = t2r_ring_sz;
	struct rpc_ringbuf *shm = t2r_ring;

	/*
	 * shm->rd may be updated by other CPUs;
	 * make sure it is visible and up to date.
	 */
	rd = smp_load_acquire(&shm->rd);

	if ((rd > ringsz) || (t2r_ring_wr > ringsz))
		return false;

	if (rd <= t2r_ring_wr)
		remain = ringsz + rd - t2r_ring_wr;
	else
		remain = rd - t2r_ring_wr;

	return remain > size;
}

/*
 * Copy data into the ring buffer and return the advanced local write pointer.
 */
static unsigned int rpc_ring_write(void *data, unsigned int size,
				   unsigned int wr)
{
	struct rpc_ringbuf *shm = t2r_ring;
	unsigned int remain = 0, ringsz = t2r_ring_sz;

	if (wr + size > ringsz) {
		remain = wr + size - ringsz;
		memcpy(&shm->mem[wr], data, size - remain);
		memcpy(&shm->mem[0], data + size - remain, remain);
		wr = remain;
	} else {
		memcpy(&shm->mem[wr], data, size);
		wr += size;
	}

	return wr;
}

static inline void rpc_ring_publish(unsigned int wr)
{
	t2r_ring_wr = wr;
	/* Publish write pointer after all payload bytes are visible. */
	smp_store_release(&t2r_ring->wr, wr);
}

int rpc_call(unsigned int id, void *data, size_t size)
{
	int ret = -EPERM;
	unsigned int wr;
	unsigned long flags = 0;
	struct rpc_cmd cmd = {0};

	if (!t2r_ring)
		return -ENXIO;

	if (!rpc_test_callee())
		return -EAGAIN;

	if (id >= MBEDTEE_RPC_MAX)
		return -EINVAL;

	if (((!data) && size) || (size > PAGE_SIZE))
		return -EINVAL;

	/* similar as TLV (NAME + SIZE + DATA) */
	spin_lock_irqsave(&rpc_lock, flags);
	if (!rpc_ring_enough(sizeof(struct rpc_cmd) + size)) {
		EMSG("rpc ring not enough\n");
		rpc_notify_callee();
		ret = -ENOMEM;
		goto out;
	}

	/* enqueue the rpc_cmd + DATA */
	cmd.id = id;
	cmd.size = size;
	cmd.waiter_id = 0; /* NULL for async-rpc */

	wr = rpc_ring_write(&cmd, sizeof(cmd), t2r_ring_wr);
	wr = rpc_ring_write(data, size, wr);
	rpc_ring_publish(wr);

	rpc_notify_callee();

	ret = 0;

out:
	spin_unlock_irqrestore(&rpc_lock, flags);
	return ret;
}

int rpc_call_sync(unsigned int id, void *data, size_t size)
{
	char *shm = NULL;
	int ret = -EPERM;
	unsigned int timeout_retry = 0;
	unsigned int wr;
	struct thread *t = current;
	unsigned long flags = 0;
	uint64_t shm_phy = 0;
	struct rpc_cmd cmd = {0};

	if (!t2r_ring)
		return -ENXIO;

	if (!rpc_test_callee())
		return -EAGAIN;

	if (id >= MBEDTEE_RPC_MAX)
		return -EINVAL;

	if ((!data) && size)
		return -EINVAL;

	spin_lock_irqsave(&rpc_lock, flags);

	if (!rpc_ring_enough(sizeof(struct rpc_cmd))) {
		EMSG("rpc ring not enough\n");
		ret = -ENOMEM;
		goto out;
	}

	if (!IS_RPC_SHM(data)) {
		shm = rpc_shm_alloc(size);
		if (!shm) {
			ret = -ENOMEM;
			goto out;
		}
		memcpy(shm, data, size);
		shm_phy = virt_to_phys(shm);
	} else {
		shm_phy = virt_to_phys(data);
	}

	t->rpc_caller = true;

	/* enqueue the rpc_cmd + DATA_PTR */
	cmd.id = id;
	cmd.size = size;
	cmd.shm = shm_phy;
	cmd.waiter_id = t->id; /* Non-NULL for sync-rpc */

	wr = rpc_ring_write(&cmd, sizeof(cmd), t2r_ring_wr);
	rpc_ring_publish(wr);

	rpc_notify_callee();

	ret = 0;

out:
	if (ret == -ENOMEM)
		rpc_notify_callee();

	spin_unlock_irqrestore(&rpc_lock, flags);

	while (wait_event_timeout(&t->wait_q,
			!t->rpc_caller, RPC_SYNC_WAIT_SLICE_US) == 0) {
		/*
		 * Lost-edge safety net: if REE missed the doorbell while this
		 * thread is waiting for completion, periodically re-send notify
		 * so pending sync RPCs still make forward progress.
		 */
		if (t->rpc_caller)
			rpc_notify_callee();

		if ((++timeout_retry % 500) == 0)
			EMSG("rpc wait timeout/re-notify - tid %d\n", t->id);
	}

	if (shm) {
		memcpy(data, shm, size);
		rpc_shm_free(shm);
	}

	return ret;
}

int rpc_complete(pid_t tid)
{
	int ret = -ESRCH;
	struct thread *t = NULL;
	unsigned long flags = 0;

	t = thread_get(tid);
	if (t) {
		spin_lock_irqsave(&rpc_lock, flags);

		if (t->rpc_caller) {
			t->rpc_caller = false;
			wakeup(&t->wait_q);
			ret = 0;
		} else {
			EMSG("rpc_caller error\n");
			ret = -EACCES;
		}

		spin_unlock_irqrestore(&rpc_lock, flags);

	} else
		EMSG("invalid tid %d\n", tid);

	thread_put(t);
	return ret;
}

static __init int rpc_shm_init(struct device_node *dn)
{
	int ret = -EPERM;
	void *start = NULL;
	void *manager = NULL;
	unsigned long addr = 0;
	size_t node_size = 128;
	size_t shm_size = 0;

	ret = of_read_property_addr_size(dn, "rpc-t2r-shm", 0, &addr, &shm_size);
	if (ret != 0) {
		EMSG("error rpc-t2r-shm dts\n");
		return ret;
	}

	start = phys_to_virt(addr);

	manager = kmalloc(buddy_mgs(shm_size, node_size));
	if (!manager) {
		ret = -ENOMEM;
		goto out;
	}

	ret = buddy_init(&t2r_shm, start, shm_size, manager, node_size);
	if (ret != 0)
		goto out;

	IMSG("rpc-t2r-shm=%p size=%ld\n", t2r_shm.start, (long)shm_size);

out:
	if (ret != 0)
		kfree(manager);
	return ret;
}

static __init void rpc_init(void)
{
	int ret = -1;
	unsigned long addr = 0;
	size_t size = 0;
	struct device_node *dn = NULL;

	dn = of_find_compatible_node(NULL, "memory");
	if (!dn)
		return;

	ret = rpc_shm_init(dn);
	if (ret != 0)
		return;

	ret = of_read_property_addr_size(dn, "rpc-t2r-ring", 0, &addr, &size);
	if (ret != 0) {
		EMSG("error rpc-t2r-ring dts\n");
		return;
	}

	t2r_ring = phys_to_virt(addr);
	t2r_ring_sz = size - sizeof(struct rpc_ringbuf);
	t2r_ring->rd = t2r_ring->wr = 0;
	t2r_ring->callee_ready = 0;
	t2r_ring->callee_hartid = 0;
	t2r_ring->callee_imsic_id = 0;

#if defined(CONFIG_ARM)
	ret = of_property_read_u32(dn, "rpc-t2r-spi", &rpc_t2r_spi);
	if (ret == 0)
		IMSG("rpc-t2r-spi=%d\n", rpc_t2r_spi);
#endif

	IMSG("rpc-t2r-ring=%p size=%ld\n", t2r_ring, (long)t2r_ring_sz);
}

MODULE_INIT_CORE(rpc_init);
