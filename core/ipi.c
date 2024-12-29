// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Inter-Processor-Interrupt Framework
 */

#include <of.h>
#include <mmu.h>
#include <timer.h>
#include <mutex.h>
#include <string.h>
#include <trace.h>
#include <cache.h>
#include <delay.h>
#include <buddy.h>
#include <sleep.h>
#include <driver.h>
#include <errno.h>
#include <thread.h>
#include <kmalloc.h>
#include <spinlock.h>
#include <interrupt.h>

#include <ipi.h>

struct ipi_hdr {
	/* callee function id */
	unsigned short id;
	/* content size of data-buffer */
	unsigned short size;
	/* if none zero, means the sync-ipi */
	unsigned int tid;
	/* data-buffer, for sync-ipi only */
	void *data;
};

struct ipi_work {
	unsigned int tid;
	/* content size of data-buffer */
	unsigned short size;
	/* data-buffer */
	void *data;
	ipi_func_t func;
	struct work work;
};

/*
 * percpu ipi ring buffer information
 */
static struct percpu_ipi {
	unsigned short wr;
	unsigned short rd;
	unsigned short size;
	struct spinlock sl;
	unsigned char *mem;
} __percpu_ipi[CONFIG_NR_CPUS] __aligned(64) = {0};

static ipi_func_t ipifuncs[IPI_NR] = {NULL};

static inline struct percpu_ipi *ipi_ringof(int cpu)
{
	return (struct percpu_ipi *)&__percpu_ipi[cpu];
}

/*
 * check if the remain ring-buff is
 * enough or not for current call
 */
static int ipi_ring_enough(struct percpu_ipi *ring,
	unsigned int size)
{
	unsigned int remain = 0;
	unsigned int wr = 0, rd = 0;

	/*
	 * ring->rd is possibly updating by other CPUs,
	 * make sure the it is visible and update to date
	 */
	smp_mb();
	wr = ring->wr;
	rd = ring->rd;

	/* ipi down */
	if (ring->mem == NULL)
		return false;

	if (rd <= wr)
		remain = ring->size + rd - wr;
	else
		remain = rd - wr;

	return (remain >= size);
}

/*
 * copy into the ring-buff and update the write ptr
 */
static void ipi_ring_write(struct percpu_ipi *ring,
	const void *data, unsigned int size)
{
	unsigned int remain = 0;
	unsigned int wr = ring->wr;

	if (wr + size > ring->size) {
		remain = wr + size - ring->size;
		memcpy(&ring->mem[wr], data, size - remain);
		memcpy(&ring->mem[0], data + size - remain, remain);
		wr = remain;
	} else {
		memcpy(&ring->mem[wr], data, size);
		wr += size;
	}

	ring->wr = wr;

	/* make sure the updates to #ring are visible to others */
	smp_mb();
}

int ipi_call(unsigned int id, unsigned int cpu,
	const void *data, size_t size)
{
	int ret = -EPERM, retrycnt = 0;
	unsigned long flags = 0;
	struct ipi_hdr hdr;
	struct percpu_ipi *ring = NULL;

	if ((size > IPI_MSG_MAX_SIZE) || (id >= IPI_NR)
		|| !cpu_online(cpu))
		return -EINVAL;

	if (!data && size)
		return -EINVAL;

	ring = ipi_ringof(cpu);

	while (++retrycnt < 20 && !ipi_ring_enough(ring,
			sizeof(struct ipi_hdr) + size)) {
		if (retrycnt == 1)
			raise_softint(SOFTINT_IPI, cpu);
		udelay(5);
	}

	spin_lock_irqsave(&ring->sl, flags);

	if (!ipi_ring_enough(ring, sizeof(struct ipi_hdr) + size)) {
		EMSG("%d ipi ring not enough, wr %d rd %d\n",
			cpu, ring->wr, ring->rd);
		ret = -ENOMEM;
		goto out;
	}

	/* similar as TLV (NAME + SIZE + DATA) */

	/* enqueue the ipi_hdr + DATA */
	hdr.id = id;
	hdr.size = size;
	hdr.tid = 0; /* tid == 0, means for async-ipi */
	ipi_ring_write(ring, (void *)&hdr, sizeof(hdr));

	if (data)
		ipi_ring_write(ring, data, size);

	ret = 0;

out:
	raise_softint(SOFTINT_IPI, cpu);
	spin_unlock_irqrestore(&ring->sl, flags);
	return ret;
}

int ipi_call_sync(unsigned int id, unsigned int cpu,
	void *data, size_t size)
{
	int ret = -EPERM, retrycnt = 0;
	struct thread *t = current;
	unsigned long flags = 0;
	struct percpu_ipi *ring = NULL;
	struct ipi_hdr hdr;

	if (!cpu_online(cpu) || (id >= IPI_NR))
		return -EINVAL;

	ring = ipi_ringof(cpu);

	while (++retrycnt < 20 && !ipi_ring_enough(ring,
			sizeof(struct ipi_hdr))) {
		if (retrycnt == 1)
			raise_softint(SOFTINT_IPI, cpu);
		usleep(100);
	}

	spin_lock_irqsave(&ring->sl, flags);
	if (!ipi_ring_enough(ring, sizeof(struct ipi_hdr))) {
		EMSG("%d ipi ring not enough, wr %d rd %d\n",
			cpu, ring->wr, ring->rd);
		ret = -ENOMEM;
		goto out;
	}

	t->wait_q.condi = false;

	/* enqueue the ipi_hdr + DATA_PTR */
	hdr.id = id;
	hdr.size = size;
	hdr.data = data;
	hdr.tid = t->id; /* tid != 0, means for sync-ipi */

	ipi_ring_write(ring, (void *)&hdr, sizeof(hdr));

	ret = 0;

out:
	raise_softint(SOFTINT_IPI, cpu);
	spin_unlock_irqrestore(&ring->sl, flags);

	if (ret == 0)
		wait(&t->wait_q);

	return ret;
}

/*
 * the following functions are for callee
 */
static void ipi_complete(pid_t id)
{
	struct thread *t = NULL;

	t = thread_get(id);
	if (t)
		wakeup(&t->wait_q);
	else
		EMSG("invalid tid %d\n", id);

	thread_put(t);
}

static inline size_t ipi_available_size(
	struct percpu_ipi *ring)
{
	unsigned int wr = 0;
	unsigned int rd = 0;
	unsigned int shm_size = ring->size;

	/*
	 * ring->wr is possibly updating by other CPUs,
	 * make sure the it is visible and update to date
	 */
	smp_mb();
	rd = ring->rd;
	wr = ring->wr;

	if (wr >= rd)
		return wr - rd;
	else
		return shm_size + wr - rd;
}

static void ipi_ring_read(
	struct percpu_ipi *ring,
	void *data, unsigned int size)
{
	unsigned int remain = 0;
	unsigned int shm_size = ring->size;
	unsigned int rd = 0;

	rd = ring->rd;
	if (rd + size <= shm_size) {
		memcpy(data, &ring->mem[rd], size);
		ring->rd += size;
	} else {
		remain = rd + size - shm_size;
		memcpy(data, &ring->mem[rd], size - remain);
		memcpy((unsigned char *)data + size - remain,
				&ring->mem[0], remain);
		ring->rd = remain;
	}

	/* make sure the update to ring->rd is visible to others */
	smp_mb();
}

static struct ipi_work *ipi_pick_next(
	struct percpu_ipi *ring,
	struct ipi_work *c,
	void *inlinebuffer)
{
	ipi_func_t func = NULL;
	struct ipi_hdr hdr;

	if (ipi_available_size(ring) < sizeof(hdr))
		return NULL;

	ipi_ring_read(ring, &hdr, sizeof(hdr));

	if (hdr.id >= IPI_NR) {
		panic("invalid ipi %d ??\n", hdr.id);
		return NULL;
	}

	if (hdr.size > ring->size)
		panic("invalid hdr %d ??\n", hdr.size);

	func = ipifuncs[hdr.id];
	if (func == NULL)
		panic("ipi %d unregister??\n", hdr.id);

	if (hdr.tid == 0) {
		/* async ipi notification from peer */
		if (hdr.size) {
			while (ipi_available_size(ring) < hdr.size)
				udelay(1);
			c->data = inlinebuffer;
			ipi_ring_read(ring, c->data, hdr.size);
		}
	} else {
		/* sync ipi notification from peer */
		while ((c = kmalloc(sizeof(*c))) == NULL)
			udelay(10);
		c->data = hdr.data;
	}

	c->size = hdr.size;
	c->tid = hdr.tid;
	c->func = func;

	return c;
}

static void ipi_yield(struct work *w)
{
	struct ipi_work *c = NULL;

	c = container_of(w, struct ipi_work, work);

	c->func(c->data, c->size);

	ipi_complete(c->tid);
	kfree(c);
}

static void ipi_isr(void *unused)
{
	struct ipi_work iw, *c = &iw;
	unsigned char buffer[IPI_MSG_MAX_SIZE];
	struct percpu_ipi *ring = ipi_ringof(percpu_id());

	while (atomic_read_x(&ring->wr) != ring->rd) {
		c = ipi_pick_next(ring, &iw, buffer);
		if (c == NULL)
			break;

		if (c->func == NULL)
			continue;

		/* no peer is waiting, it's asynchronous ipi */
		if (c->tid == 0) {
			c->func(c->data, c->size);
		} else {
			/* peer is waiting, it's synchronous ipi */
			INIT_WORK(&c->work, ipi_yield);
			schedule_highpri_work_on(percpu_id(), &c->work);
		}
	}
}

int ipi_register(unsigned int id, ipi_func_t func)
{
	if (id >= IPI_NR)
		return -EINVAL;

	ipifuncs[id] = func;
	return 0;
}

void ipi_unregister(unsigned int id)
{
	if (id < IPI_NR)
		ipifuncs[id] = NULL;
}

void ipi_init(void)
{
	unsigned long flags = 0;
	struct percpu_ipi *ring = NULL;

	ring = ipi_ringof(percpu_id());

	spin_lock_irqsave(&ring->sl, flags);

	ring->rd = ring->wr = 0;
	ring->size = 256 * sizeof(long);
	ring->mem = kmalloc(ring->size);

	spin_unlock_irqrestore(&ring->sl, flags);

	if (register_softint(SOFTINT_IPI, ipi_isr, NULL) < 0)
		cpu_set_error();

	if (ring->mem == NULL)
		cpu_set_error();
}

/*
 * For CPU Hot-Plug
 * free the ipi resource (ring buffer)
 */
void ipi_down(void)
{
	struct percpu_ipi *ring = ipi_ringof(percpu_id());
	unsigned char *mem = ring->mem;

	spin_lock(&ring->sl);
	ring->mem = NULL;
	ring->size = 0;
	ring->rd = ring->wr = 0;
	spin_unlock(&ring->sl);

	kfree(mem);
}
