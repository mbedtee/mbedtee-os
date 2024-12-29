/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 memory map (layout / Address Spaces)
 */

#ifndef _MAP_H
#define _MAP_H

#include <defs.h>
#include <generated/autoconf.h>

/*
 * phys/virt runs at same address
 */
#define VA_OFFSET	CONFIG_OS_ADDR
#define PA_OFFSET	VA_OFFSET

#ifndef __ASSEMBLY__

extern unsigned long __memstart;

/*
 * convert the kernel phys/virt addresses
 */
#define phys_to_virt(x) ((void *)(((unsigned long)(x) - PA_OFFSET) + VA_OFFSET))
#define virt_to_phys(x) (((unsigned long)(x) - VA_OFFSET) + PA_OFFSET)

/*
 * phys_to_dma and dma_to_phys depends on the SoC design
 *
 * 0xA0000000 doesn't mean KSEG1 here, DMA addr is 0x20000000
 * 0xC0000000 doesn't mean KSEG2 here, DMA addr is 0x40000000
 */
#define phys_to_dma(x) ((unsigned long)(x) & UL(0x7FFFFFFF))
#define dma_to_phys(x) ((unsigned long)(x) | UL(0x80000000))
#endif

/*
 * 2GB for user space, 2GB for kernel space
 */
#define USER_VA_TOP				UL(0x80000000)

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
 * At least (2048M - 64M - 512M - 256M - 1M) = 1215M
 */
#define USER_HEAP_SIZE          (USER_VA_TOP - USER_VM4REE_SIZE - \
								USER_VM4TEE_SIZE - USER_ASLR_SIZE - UL(0x100000))
#define USER_HEAP_VA(p)         (UL(0x100000) + (p)->aslr)

/*
 * Kernel virtual address space - 128M (vmalloc/iomap etc.)
 *  0xF8000000 ~ 0xFFFFFFFF
 */
#define KERN_VMA_SIZE UL(0x04000000)
#define KERN_VMA_START (-KERN_VMA_SIZE)

#endif
