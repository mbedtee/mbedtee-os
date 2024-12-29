/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel memory management
 */

#ifndef _MEM_H
#define _MEM_H

#include <stddef.h>

#define MEM_TYPE_RESERVED	0
#define MEM_TYPE_COMBO		1
#define MEM_TYPE_HEAP		2
#define MEM_TYPE_FS			3

/*
 *  This structure has information about the
 *  memory regions in the secure world
 */
struct mem_region {
	struct mem_region *next;
	unsigned char type;
	unsigned long start;
	unsigned long size;
};

extern size_t mem_size;

void mem_init(void);
void mem_info(void);
int map_kern(void);
int mem_early_init(void);

int mem_register(int type, unsigned long pa, size_t size);

int mem_in_secure(unsigned long pa);
int mem_overlap_secure(unsigned long pa, size_t size);

#endif
