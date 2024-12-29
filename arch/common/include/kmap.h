/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel memory map/unmap (with flexible flags)
 * device-IO map/unmap (None-Cacheable)
 */

#ifndef _KMAP_H
#define _KMAP_H

#include <stddef.h>

/*
 * map the memory-phys to a high virtual space
 * return the high virtual address
 *
 * #pa/#size must be aligned to page bounds
 */
void *kmap(unsigned long pa, size_t size, int flags);

/*
 * unmap and free the va
 */
void kunmap(void *kva, size_t size);

/*
 * map the dev-phys to a high virtual space
 * return the non-cacheable high virtual address
 */
void *iomap(unsigned long pa, size_t size);

/*
 * unmap and free the va
 */
void iounmap(void *va, size_t size);

#endif
