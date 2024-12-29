// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RPC Caller (TEE->REE)
 */

#include <of.h>
#include <mmu.h>
#include <timer.h>
#include <mutex.h>
#include <errno.h>
#include <string.h>
#include <trace.h>
#include <cache.h>
#include <delay.h>
#include <buddy.h>
#include <sleep.h>
#include <driver.h>
#include <thread.h>
#include <kmalloc.h>
#include <spinlock.h>
#include <interrupt.h>

#include <rpc.h>

static SPIN_LOCK(rpc_lock);
static SPIN_LOCK(rpcshm_lock);
static unsigned int t2r_ring_sz;
static struct rpc_ringbuf *t2r_ring;
static struct buddy_pool t2r_shm = {0};

#define IS_RPC_SHM(x) (((x) >= t2r_shm.start) && \
	((x) < t2r_shm.start + (1ul << t2r_shm.order)))

void *rpc_shm_alloc(size_t size)
{
	void *shm = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&rpcshm_lock, flags);

	shm = buddy_alloc(&t2r_shm, size);

	spin_unlock_irqrestore(&rpcshm_lock, flags);

	if (shm == NULL)
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
 * check if the remain ring-buff is
 * enough or not for current call
 */
static int rpc_ring_enough(unsigned int size)
{
	unsigned int wr = 0, rd = 0;
	unsigned int remain = 0, ringsz = t2r_ring_sz;
	struct rpc_ringbuf *shm = t2r_ring;

	/*
	 * shm->rd is possibly updating by other CPUs,
	 * make sure the it is visible and update to date
	 */
	smp_mb();
	wr = shm->wr;
	rd = shm->rd;

	if ((rd > ringsz) || (wr > ringsz))
		return false;

	if (rd <= wr)
		remain = ringsz + rd - wr;
	else
		remain = rd - wr;

	return remain >= size;
}

/*
 * copy into the ring-buff,
 * and update the write ptr
 */
static void rpc_ring_write(void *data, unsigned int size)
{
	struct rpc_ringbuf *shm = t2r_ring;
	unsigned int remain = 0, ringsz = t2r_ring_sz;
	static unsigned int wr;

	if (wr + size > ringsz) {
		remain = wr + size - ringsz;
		memcpy(&shm->mem[wr], data, size - remain);
		memcpy(&shm->mem[0], data + size - remain, remain);
		wr = remain;
	} else {
		memcpy(&shm->mem[wr], data, size);
		wr += size;
	}

	shm->wr = wr;

	/* make sure the updates to #t2r_ring are visible to others */
	smp_mb();
}

int rpc_call(unsigned int id, void *data, size_t size)
{
	int ret = -EPERM;
	unsigned long flags = 0;
	struct rpc_cmd cmd = {0};

	if (!t2r_ring)
		return -ENOMSG;

	if (id >= RPC_REENR)
		return -EINVAL;

	if (((!data) && size) || (size > PAGE_SIZE))
		return -EINVAL;

	/* similar as TLV (NAME + SIZE + DATA) */
	spin_lock_irqsave(&rpc_lock, flags);
	if (!rpc_ring_enough(sizeof(struct rpc_cmd) + size)) {
		EMSG("rpc ring not enough\n");
		raise_softint(SOFTINT_RPC_CALLER, percpu_id());
		ret = -ENOMEM;
		goto out;
	}

	/* enqueue the rpc_cmd + DATA */
	cmd.id = id;
	cmd.size = size;
	cmd.waiter = 0; /* NULL for async-rpc */

	rpc_ring_write((void *)&cmd, sizeof(cmd));
	rpc_ring_write(data, size);

	raise_softint(SOFTINT_RPC_CALLER, percpu_id());

	ret = 0;

out:
	spin_unlock_irqrestore(&rpc_lock, flags);
	return ret;
}

int rpc_call_sync(unsigned int id, void *data, size_t size)
{
	char *shm = NULL;
	int ret = -EPERM;
	struct thread *t = current;
	unsigned long flags = 0, shm_phy = 0;
	struct rpc_cmd cmd = {0};

	if (!t2r_ring)
		return -ENXIO;

	if (id >= RPC_REENR)
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
		if (shm == NULL) {
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
	cmd.waiter = t->id; /* Non-NULL for sync-rpc */

	rpc_ring_write((void *)&cmd, sizeof(cmd));

	raise_softint(SOFTINT_RPC_CALLER, percpu_id());

	ret = 0;

out:
	if (ret == -ENOMEM)
		raise_softint(SOFTINT_RPC_CALLER, percpu_id());

	spin_unlock_irqrestore(&rpc_lock, flags);

	if (ret == 0)
		wait_event(&t->wait_q, t->rpc_caller == false);

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

static __init int rpc_shm_init(struct device *dev)
{
	int ret = -EPERM;
	void *start = NULL;
	void *manager = NULL;
	int naddr = 0, nsize = 0, plen = 0;
	struct device_node *dn = NULL;
	const unsigned int *range = NULL;
	size_t node_size = 128;
	size_t shm_size = 0;

	dn = container_of(dev, struct device_node, dev);
	naddr = of_n_addr_cells(dn);
	nsize = of_n_size_cells(dn);

	range = of_get_property(dn, "rpc-t2r-shm", &plen);
	if (range == NULL || (plen/sizeof(int) != naddr + nsize)) {
		EMSG("error rpc-t2r-shm dts\n");
		return ret;
	}

	start = phys_to_virt(of_read_ulong(range, naddr));
	shm_size = of_read_ulong(range + naddr, nsize);

	manager = kmalloc(buddy_mgs(shm_size, node_size));
	if (manager == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ret = buddy_init(&t2r_shm, start, shm_size, manager, node_size);
	if (ret != 0)
		goto out;

	IMSG("rpc-t2r-shm=%p size=%ld\n", t2r_shm.start, (long)shm_size);

out:
	if (ret)
		kfree(manager);
	return ret;
}

static __init int rpc_init(struct device *dev)
{
	struct device_node *dn = NULL;
	int ret = -1, naddr = 0, nsize = 0, plen = 0;
	const unsigned int *range = NULL;

	ret = rpc_shm_init(dev);
	if (ret != 0)
		return ret;

	dn = container_of(dev, struct device_node, dev);
	naddr = of_n_addr_cells(dn);
	nsize = of_n_size_cells(dn);

	range = of_get_property(dn, "rpc-t2r-ring", &plen);
	if (range == NULL || (plen/sizeof(int) != naddr + nsize)) {
		EMSG("error rpc-t2r-ring dts\n");
		return ret;
	}

	t2r_ring = phys_to_virt(of_read_ulong(range, naddr));
	t2r_ring_sz = of_read_ulong(range + naddr, nsize);
	t2r_ring_sz -= sizeof(struct rpc_ringbuf);
	t2r_ring->rd = t2r_ring->wr = 0;

	register_softint(SOFTINT_RPC_CALLER, NULL, NULL);

	IMSG("rpc-t2r-ring=%p size=%ld\n", t2r_ring, (long)t2r_ring_sz);

	return 0;
}

static const struct of_device_id of_rpc_caller_id[] = {
	{.name = "memory", .compat = "memory"},
	{},
};

static const struct device_driver of_rpc_caller = {
	.name = "rpc-caller",
	.probe = rpc_init,
	.of_match_table = of_rpc_caller_id,
};

module_core(of_rpc_caller);
