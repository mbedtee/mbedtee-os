/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV64 memory map (layout / Address Spaces)
 */

#ifndef _MAP_H
#define _MAP_H

#include <defs.h>
#include <generated/autoconf.h>

/*
 * Currently only support 39bits (Sv39)
 *
 * Address space up to (VA_BITS) bits (Total 512GB)
 * 256GB for user space, 256GB for kernel space
 *
 * for User    -- 0x00000000_00000000 ~ 0x0000003F_FFFFFFFF
 * for kernel  -- 0xFFFFFFC0_00000000 ~ 0xFFFFFFFF_FFFFFFFF
 */
#define VA_BITS		CONFIG_VA_BITS

/*
 * Must be at least 2MB aligned
 * Default value from memnuconfig: started from 128GB -> 0xFFFFFFE0_00000000
 */
#define VA_OFFSET	CONFIG_OS_ADDR

#define PA_MASK		((UL(1) << (56)) - 1)

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
#define phys_to_virt(x) ((void *)(((unsigned long)(x) - PA_OFFSET) + VA_OFFSET))
#define virt_to_phys(x) (((unsigned long)(x) - VA_OFFSET) + PA_OFFSET)

/*
 * phys_to_dma and dma_to_phys depends on the SoC design
 *
 * e.g. the riscv64 virt platform uses the following design:
 ** DRAM, 0GB-32GB  0x00_8000_0000 ~ 0x08_7FFF_FFFF (linear mapping)
 */
#define phys_to_dma(x) ((unsigned long)(x) - UL(0x80000000))
#define dma_to_phys(x) ((unsigned long)(x) + UL(0x80000000))

/*
 * assume the max physical memory is 128GB
 *
 * Case 1: VA_OFFSET = 0xFFFFFFE0_00000000, PA_OFFSET=0x80000000
 * PA [0x80000000 ~ 0x20_7FFFFFFF] --> VA [0xFFFFFFE0_00000000 ~ 0xFFFFFFFF_FFFFFFFF]
 *
 * Case 2: VA_OFFSET = 0xFFFFFFE0_00000000, PA_OFFSET=0x80200000
 * PA [0x80200000 ~ 0x20_7FFFFFFF] --> VA [0xFFFFFFE0_00000000 ~ 0xFFFFFFFF_FFDFFFFF]
 * PA [0x80000000 ~ 0x801FFFFF] --> VA [0xFFFFFFDF_FFE00000 ~ 0xFFFFFFDF_FFFFFFFF]
 */
#endif

/*
 * 256GB for user space, 256GB for kernel space
 * User: 0x0000000000 ~ (0x4000000000 - 1)
 */
#define USER_VA_TOP             (UL(1) << (VA_BITS - 1))

#define KERN_VA_START           (USER_VA_TOP - (UL(1) << (VA_BITS)))

/*
 * 16G for each process's ASLR space
 */
#ifdef CONFIG_ASLR
#define USER_ASLR_SIZE          UL(0x0400000000)
#else
#define USER_ASLR_SIZE          UL(0x0000000000)
#endif

/* UserProcess(app) VMA space for REE mmeory - 32GB */
#define USER_VM4REE_SIZE        UL(0x0800000000)
#define USER_VM4REE_VA(p)       (USER_VA_TOP - USER_VM4REE_SIZE - USER_ASLR_SIZE + (p)->aslr)

/* UserProcess(app) VMA space for TEE memory - 128GB */
#define USER_VM4TEE_SIZE        UL(0x2000000000)
#define USER_VM4TEE_VA(p)       (USER_VM4REE_VA(p) - USER_VM4TEE_SIZE)

/*
 * UserProcess(app) heap size (0 ~ 1G is reserved)
 * At least (256G - 16G - 32G - 128G - 1G) = 79G
 */
#define USER_HEAP_SIZE          (USER_VA_TOP - USER_ASLR_SIZE - USER_VM4REE_SIZE \
								- USER_VM4TEE_SIZE - UL(0x40000000))
#define USER_HEAP_VA(p)         (UL(0x40000000) + (p)->aslr)

/*
 * Kernel virtual address space - 64G (vmalloc/iomap etc.)
 * e.g. 0xFFFFFFD0_00000000 ~ (0xFFFFFFE0_00000000 - 1)
 * phys_to_virt(0) -> means vma_start nexts to the lowest VA
 */
#define KERN_VMA_SIZE UL(0x1000000000)
#define KERN_VMA_START ((unsigned long)(phys_to_virt(0) - KERN_VMA_SIZE) >= KERN_VA_START \
	 ? ((unsigned long)phys_to_virt(0) - KERN_VMA_SIZE) : (-KERN_VMA_SIZE))
#endif
