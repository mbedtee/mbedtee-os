// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel memory map/unmap (with flexible flags)
 * device-IO map/unmap (None-Cacheable)
 */

#include <page.h>
#include <kvma.h>
#include <kproc.h>
#include <kmap.h>
#include <trace.h>

#include <generated/autoconf.h>

void *kmap(unsigned long pa, size_t size, int flags)
{
	void *kva = NULL;

#if defined(CONFIG_MMU)
	kva = kvma_alloc(size);

	if (kva) {
		if (map(kpt(), pa, kva, size, flags) != 0) {
			kvma_free(kva);
			return NULL;
		}
	}
#endif

	return kva;
}

void kunmap(void *kva, size_t size)
{
#if defined(CONFIG_MMU)
	unmap(kpt(), kva, size);
	kvma_free(kva);
#endif
}

/*
 * return the non-cacheable IO address
 */
void *iomap(unsigned long pa, size_t size)
{
#if defined(CONFIG_MMU) && !defined(CONFIG_MIPS)
	void *va = NULL;

	if (pa && size) {
		if (((pa & (~PAGE_MASK)) + (size & (~PAGE_MASK))) > PAGE_SIZE)
			size += PAGE_SIZE;
		size = roundup(size, PAGE_SIZE);

		va = kvma_alloc(size);

		if (va) {
			if (map(kpt(), rounddown(pa, PAGE_SIZE),
				va, size, PG_RW | PG_DMA) != 0) {
				kvma_free(va);
				return NULL;
			}
			va += (pa % PAGE_SIZE);
		}
	}

	return va;
#endif /* CONFIG_MMU -> CONFIG_ARM / CONFIG_RISCV */

#if defined(CONFIG_MIPS) /* MIPS has fix-mapping-table */
	return (void *)(UL(0xA0000000) | (pa));
#endif

	return (void *)pa;
}

/*
 * unmap and free the va
 */
void iounmap(void *va, size_t size)
{
#if defined(CONFIG_MMU) && !defined(CONFIG_MIPS)
	unsigned long vv = (unsigned long)va;

	if (((vv & (~PAGE_MASK)) +
		(size & (~PAGE_MASK))) > PAGE_SIZE)
		size += PAGE_SIZE;

	size = roundup(size, PAGE_SIZE);

	va = (void *)(vv & PAGE_MASK);
	if (va && size) {
		unmap(kpt(), va, size);
		kvma_free(va);
	}
#endif
}
