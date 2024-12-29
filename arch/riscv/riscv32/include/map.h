/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV32 memory map (layout / Address Spaces)
 */

#ifndef _MAP_H
#define _MAP_H

#include <defs.h>
#include <generated/autoconf.h>

/*
 * Limitation 1: Max to 2G memory supported
 * Limitation 2: VA_OFFSET and PA_OFFSET must be SECTION aligned
 * Limitation 3: VA_OFFSET must be big than or equal to PA_OFFSET
 *
 * Major possible cases:
 *
 * Case 1: VA_OFFSET == PA_OFFSET
 * e.g. VA_OFFSET = 0x80000000, PA_OFFSET=0x80000000
 * e.g. VA_OFFSET = 0xC0000000, PA_OFFSET=0xC0000000
 * PA [0x80000000 ~ 0xFFFFFFFF] --> VA [0x80000000 ~ 0xFFFFFFFF]
 *
 * Case 2: VA_OFFSET = 0xC0000000, PA_OFFSET=0x80000000
 * PA [0x80000000 ~ 0xBFFFFFFF] --> VA [0xC0000000 ~ 0xFFFFFFFF]
 * PA [0xC0000000 ~ 0xFFFFFFFF] --> VA [0x80000000 ~ 0xBFFFFFFF]
 *
 * Case 3: VA_OFFSET = 0xC0000000, PA_OFFSET=0x80100000
 * PA [0x80100000 ~ 0xC00FFFFF] --> VA [0xC0000000 ~ 0xFFFFFFFF]
 * PA [0xC0100000 ~ 0xFFFFFFFF] --> VA [0x80000000 ~ 0xBFEFFFFF]
 * PA [0x80000000 ~ 0x800FFFFF] --> VA [0xBFF00000 ~ 0xBFFFFFFF]
 *
 */
#define VA_OFFSET   CONFIG_OS_ADDR

#ifndef __ASSEMBLY__

#if defined(CONFIG_MMU)
/*
 * physical memory start address to place the OS image
 */
extern unsigned long __memstart;
#define PA_OFFSET   (__memstart)
#else
#define PA_OFFSET   VA_OFFSET
#endif

/*
 * convert the kernel phys/virt addresses
 */
#define __phys_to_virt(x) (((unsigned long)(x) - PA_OFFSET) + VA_OFFSET)
#define __virt_to_phys(x) (((unsigned long)(x) - VA_OFFSET) + PA_OFFSET)

#define phys_to_virt(x) ({unsigned long v = __phys_to_virt(x); \
	(void *)((v < UL(0x80000000)) ? v + UL(0x80000000) : v); })

#define virt_to_phys(x) ({unsigned long p = __virt_to_phys(x); \
	(p < UL(0x80000000)) ? p + UL(0x80000000) : p; })

/*
 * phys_to_dma and dma_to_phys depends on the SoC design
 */
#define phys_to_dma(x) ((unsigned long)(x) & UL(0x7FFFFFFF))
#define dma_to_phys(x) ((unsigned long)(x) | UL(0x80000000))
#endif

/*
 * 2GB for user space, 2GB for kernel space
 */
#define USER_VA_TOP             UL(0x80000000)

/*
 * 256M for each process's ASLR space
 */
#ifdef CONFIG_ASLR
#define USER_ASLR_SIZE          UL(0x10000000)
#else
#define USER_ASLR_SIZE          UL(0x00000000)
#endif

/* UserProcess(app) VMA space for REE mmeory - 64M */
#define USER_VM4REE_SIZE        UL(0x04000000)
#define USER_VM4REE_VA(p)       (USER_VA_TOP - USER_VM4REE_SIZE - USER_ASLR_SIZE + (p)->aslr)

/* UserProcess(app) VMA space for TEE memory - 512M */
#define USER_VM4TEE_SIZE        UL(0x20000000)
#define USER_VM4TEE_VA(p)       (USER_VM4REE_VA(p) - USER_VM4TEE_SIZE)

/*
 * UserProcess(app) heap size (0 ~ 0x100000 is reserved)
 * At least (2048M - 128M - 64M - 512M - 1M) = 1215M
 */
#define USER_HEAP_SIZE          (USER_VA_TOP - USER_ASLR_SIZE - USER_VM4REE_SIZE \
								- USER_VM4TEE_SIZE - UL(0x100000))
#define USER_HEAP_VA(p)         (UL(0x100000) + (p)->aslr)

/*
 * Kernel virtual address space - 64M (vmalloc/iomap etc.)
 */
#define KERN_VMA_SIZE UL(0x04000000)
#define KERN_VMA_START ((unsigned long)phys_to_virt(UL(-1)) - KERN_VMA_SIZE + 1)

#endif
