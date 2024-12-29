// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel memory management
 */

#include <of.h>
#include <mem.h>
#include <mmu.h>
#include <kvma.h>
#include <string.h>
#include <trace.h>
#include <percpu.h>
#include <thread.h>
#include <device.h>
#include <kmalloc.h>
#include <sections.h>

static SPIN_LOCK(mem_lock);

static struct mem_region *mems;

static const char * const memtypes[] = {
	"Resved", "Combo", "PagePool", "RAMFS"
};

size_t mem_size;

static inline int __init mem_mapping(void)
{
	int ret = 0;

#if defined(CONFIG_MMU)
	unsigned long addr = 0;
	size_t size = 0;
	size_t nrbytes = 0;
	struct pt_struct *pt = kpt();
	size_t block_size = mmu_section_size();
	size_t block_mask = block_size - 1;

	/*
	 * Overall Mapping for SoC installed memory, thus OS
	 * is default able to access all of the installed memory.
	 * (just like the MIPS fix-mapping-table)
	 *
	 * Mandatory node for ARM/RISCV, MIPS SoC does not require it,
	 * since MIPS already has the fix-mapping-table in MMU.
	 *
	 * e.g. AArch64 FVP with 8GB memory, DTS coding:
	 *
	 * mapping = <0 0x80000000 0 0x80000000>,
	 *		     <8 0x80000000 1 0x80000000>;
	 *
	 * e.g. AArch32@ARMV7-A FVP with 2G Bytes memory installed:
	 *
	 * mapping = <0x80000000 0x80000000>;
	 *
	 * e.g. riscv32 QEMU Virt platform with 2G Bytes memory installed:
	 *
	 * mapping = <0x80000000 0x80000000>;
	 *
	 * e.g. riscv64 QEMU Virt platform with 8G Bytes memory installed:
	 *
	 * mapping = <0 0x80000000 2 0x80000000>;
	 *
	 */
	for_each_matching_addr_size("memory", "mapping", addr, size) {
		if (!addr || !size)
			continue;

		if (addr <= PA_OFFSET) {
			/* map the gap @ header */
			while ((addr < PA_OFFSET) && !ret && size) {
				nrbytes = min((size_t)(block_size - (addr & block_mask)), size);
				nrbytes = min(nrbytes, (size_t)(PA_OFFSET - addr));
				ret |= map(pt, addr, phys_to_virt(addr), nrbytes, PG_RW);
				addr += nrbytes;
				size -= nrbytes;
			}

			if (size == 0)
				continue;

			/* map the .data / .bss and all others */
			addr = virt_to_phys(__data_start());
			size -= addr - PA_OFFSET;
			while (size && !ret) {
				nrbytes = min((size_t)(block_size - (addr & block_mask)), size);
				ret |= map(pt, addr, phys_to_virt(addr), nrbytes, PG_RW);
				addr += nrbytes;
				size -= nrbytes;
			}
		} else {
			while (size && !ret) {
				nrbytes = min((size_t)(block_size - (addr & block_mask)), size);
				ret |= map(pt, addr, phys_to_virt(addr), nrbytes, PG_RW);
				addr += nrbytes;
				size -= nrbytes;
			}
		}
	}

	/* .data / .bss not covered by dts memory mapping ? check it ... */
	addr = __data_start();
	size = __code_end() - addr;
	if (!access_kern_ok((void *)addr, size, PG_RW)) {
		addr = virt_to_phys(addr);
		while (size) {
			nrbytes = min((size_t)(block_size - (addr & block_mask)), size);
			map(pt, addr, phys_to_virt(addr), nrbytes, PG_RW);
			addr += nrbytes;
			size -= nrbytes;
		}
	}

	/* in case of the kernel VMA area overlaps the physical memory */
	if (access_kern_ok((void *)KERN_VMA_START, 1, PG_RW))
		unmap(pt, (void *)KERN_VMA_START, KERN_VMA_SIZE);
#endif

	return ret;
}

/*
 * 1. map the OS code sections
 * 2. map all the mapping described in DTS
 * 3. switch from __kern_early_pgtbl to __kern_pgtbl
 */
int __init map_kern(void)
{
	int ret = 0;

#if defined(CONFIG_MMU)
	unsigned long va = 0;
	struct pt_struct *pt = kpt();

	va = __text_start(); /* equal to __code_start() */
	/* .text */
	ret |= map(pt, PA_OFFSET, (void *)va, __text_size(),
				PG_RO | PG_EXEC);

	/* .rodata */
	va = __rodata_start();
	ret |= map(pt, virt_to_phys(va), (void *)va, __rodata_size(),
				PG_RO);

	/* init and mod init section */
	va = __init_start();
	ret |= map(pt, virt_to_phys(va), (void *)va, __init_size(),
				PG_RO | PG_EXEC);

	ret |= mem_mapping();

	if (ret != 0)
		return ret;

	/* finally switch from __kern_early_pgtbl to __kern_pgtbl */
	mmu_init();
#endif

	return ret;
}

void __init mem_info(void)
{
	struct mem_region *m = mems;

	while (m != NULL) {
		IMSG("%s: Start = 0x%lx, Size = 0x%lx\n",
			memtypes[m->type], m->start, m->size);
		m = m->next;
	}

	IMSG(".text   0x%lx - 0x%lx\n", __text_start(), __text_size());
	IMSG(".rodata 0x%lx - 0x%lx\n", __rodata_start(), __rodata_size());
	IMSG(".init   0x%lx - 0x%lx\n", __init_start(), __init_size());
	IMSG(".ramfs  0x%lx - 0x%lx\n", __ramfs_start(), __ramfs_size());
	IMSG(".data   0x%lx - 0x%lx\n", __data_start(), __data_size());
	IMSG(".bss    0x%lx - 0x%lx\n", __bss_start(), __bss_size());
	IMSG(".end    0x%lx - 0x%lx\n", __code_end(), __code_size());
}

/*
 * If there are other memory regions dedicated for security purpose,
 * driver programmer can register the check as following, e.g. secure-buffer.
 *
 *	size_t size = 0;
 *	unsigned long start = 0;
 *	struct device_node *dn = NULL;
 *
 *	dn = of_find_compatible_node(NULL, "memory");
 *
 *	if (of_read_property_addr_size(dn, "secure-buffer", 0, &start, &size))
 *		return -EINVAL;
 *
 *	mem_register(MEM_TYPE_RESERVED, start, size);
 */
int mem_register(int type, unsigned long pa, size_t size)
{
	int ret = -1;
	struct mem_region *m = NULL, *n = NULL;
	unsigned long flags = 0;

	m = kmalloc(sizeof(struct mem_region));

	assert(m != NULL);

	m->start = pa;
	m->size = size;
	m->type = type;
	m->next = NULL;

	ret = 0;

	spin_lock_irqsave(&mem_lock, flags);

	n = mems;

	if (n == NULL)
		mems = m;
	else {
		while (n->next != NULL)
			n = n->next;
		n->next = m;
	}

	IMSG("%s: Start = 0x%lx, Size = 0x%lx\n",
			memtypes[m->type], m->start, m->size);

	spin_unlock_irqrestore(&mem_lock, flags);
	return ret;
}

/*
 * register necessary regions
 */
int __init mem_early_init(void)
{
	int ret = 0;
	unsigned long code_start = PA_OFFSET;
	unsigned long code_end = code_start + __code_size();
	unsigned long start = 0, end = 0;
	size_t size = 0, type = 0;

	of_for_each_matching_addr_size("memory", "reg", start, size) {
		if (!start || !size)
			continue;

		mem_size += size;

		end = start + size - 1;

		/* entirely not overlap with code */
		if ((end < code_start) || (start > code_end)) {
			type = MEM_TYPE_HEAP;

#if defined(CONFIG_MMU)
			ret |= map_early(start, size, PG_RW);
#endif
			ret |= page_pool_add(start, size);
		} else {
			type = MEM_TYPE_COMBO;

#if defined(CONFIG_MMU)
			ret |= map_early(start, size, PG_RW | PG_EXEC);
#endif

			/* partially overlap with code ? */
			if (code_end < end)
				ret |= page_pool_add(code_end, end - code_end + 1);

			/*
			 * code physical loading-address is stored at
			 * '__memstart' == code_start, instead of the
			 * mem-reg-node-start at DTS, if there is a gap
			 * between 'mem-reg-node-start' and '__memstart',
			 * register it as page pool -- heap
			 */
			if (code_start > start)
				ret |= page_pool_add(start, code_start - start);
		}

		ret |= mem_register(type, start, size);
		if (ret != 0)
			break;
	}

	if (!mem_in_secure(code_start) ||
		!mem_in_secure(code_end - 1))
		ret |= mem_register(MEM_TYPE_RESERVED,
				code_start, __code_size());

	return ret;
}

static int mem_debugfs_info(struct debugfs_file *d)
{
	/* collects the memory related information */
	kmalloc_info(d);
	page_info(d);
	kvma_info(d);

	return 0;
}

void __init mem_init(void)
{
	static const struct debugfs_fops mem_info_ops = {
		.read = mem_debugfs_info,
		.write = NULL,
	};

	debugfs_create("/mem", &mem_info_ops);
}

/*
 * PA inside one of the secure memory regions
 */
int mem_in_secure(unsigned long pa)
{
	struct mem_region *m = mems;

	while (m != NULL) {
		if (pa >= m->start &&
			pa <= m->start + m->size - 1)
			return true;
		m = m->next;
	}

	return false;
}

/*
 * PA full-cover or partly-overlap one of the OS' memory regions
 */
int mem_overlap_secure(unsigned long pa, size_t size)
{
	struct mem_region *m = mems;
	unsigned long end = pa + size - 1;

	if (size == 0)
		return false;

	if (end < pa)
		return true;

	while (m != NULL) {
		if (pa < m->start &&
			end >= m->start + m->size - 1)
			return true;
		if ((pa >= m->start && pa <= m->start + m->size - 1) !=
			(end >= m->start && end <= m->start + m->size - 1))
			return true;

		m = m->next;
	}

	return false;
}
