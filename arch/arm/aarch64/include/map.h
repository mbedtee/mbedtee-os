/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch64 memory map (layout / Address Spaces)
 */

#ifndef _MAP_H
#define _MAP_H

#include <defs.h>
#include <generated/autoconf.h>

/*
 * Currently only support 39bits
 *
 * Address space up to (VA_BITS) bits (both ttbr0/1)
 * 512GB for user space, 512GB for kernel space
 *
 * TTBR0 for User    -- 0x00000000_00000000 ~ 0x0000007F_FFFFFFFF
 * TTBR1 for kernel  -- 0xFFFFFF80_00000000 ~ 0xFFFFFFFF_FFFFFFFF
 */
#define VA_BITS   CONFIG_VA_BITS

/*
 * Must be at least 2MB aligned
 * Default value from memnuconfig: started from 256GB -> 0xFFFFFFC0_00000000
 */
#define VA_OFFSET CONFIG_OS_ADDR

#define PA_MASK   ((UL(1) << (VA_BITS)) - 1)

#ifndef __ASSEMBLY__

#if defined(CONFIG_MMU)
/*
 * physical memory start address to place the OS image
 */
extern unsigned long __memstart;
#define PA_OFFSET (__memstart)
#else
#define PA_OFFSET (VA_OFFSET)
#endif

/*
 * convert the kernel phys/virt addresses
 */
#define phys_to_virt(x) ((void *)(((unsigned long)(x) - PA_OFFSET) + VA_OFFSET))
#define virt_to_phys(x) (((unsigned long)(x) - VA_OFFSET) + PA_OFFSET)

/*
 * phys_to_dma and dma_to_phys depends on the SoC design
 *
 * e.g. the AArch64 FVP uses the following design (non-linear):
 ** DRAM, 0GB-2GB  0x00_8000_0000 ~ 0x00_FFFF_FFFF
 ** DRAM, 2GB-32GB 0x08_8000_0000 ~ 0x0F_FFFF_FFFF
 */
#define phys_to_dma(x) ({ unsigned long _x = (unsigned long)(x); \
	(_x <= UINT32_MAX) ? (_x & UL(0x7FFFFFFF)) : (_x & UL(0x7FFFFFFFF)); })
#define dma_to_phys(x) ({ unsigned long _x = (unsigned long)(x); \
	(_x <= INT32_MAX) ? (_x | UL(0x80000000)) : (_x | UL(0x800000000)); })

/*
 * Case 1: VA_OFFSET = 0xFFFFFFC0_00000000, PA_OFFSET=0x80000000
 * PA [0x80000000 ~ 0xFFFFFFFF] --> VA [0xFFFFFFC0_00000000 ~ 0xFFFFFFC0_FFFFFFFF]
 * PA [0x8_80000000 ~ 0xF_FFFFFFFF] --> VA [0xFFFFFFC8_00000000 ~ 0xFFFFFFCF_7FFFFFFF]
 *
 * Case 2: VA_OFFSET = 0xFFFFFFC0_00000000, PA_OFFSET=0x80200000
 * PA [0x80200000 ~ 0xFFFFFFFF] --> VA [0xFFFFFFC0_00000000 ~ 0xFFFFFFC0_FFDFFFFF]
 * PA [0x80000000 ~ 0x801FFFFF] --> VA [0xFFFFFFBF_FFE00000 ~ 0xFFFFFFBF_FFFFFFFF]
 * PA [0x8_80000000 ~ 0xF_FFFFFFFF] --> VA [0xFFFFFFC7_FFE00000 ~ 0xFFFFFFCF_7FDFFFFF]
 *
 * Case 3: VA_OFFSET = 0xFFFFFFC0_00000000, PA_OFFSET=0x8_80000000
 * PA [0x80000000 ~ 0xFFFFFFFF] --> VA [0xFFFFFFB8_00000000 ~ 0xFFFFFFB8_7FFFFFFF]
 * PA [0x8_80000000 ~ 0xF_FFFFFFFF] --> VA [0xFFFFFFC0_00000000 ~ 0xFFFFFFC7_7FFFFFFF]
 */
#endif

/*
 * 512GB for user space, 512GB for kernel space
 * UserSpace: 0x0000000000 ~ (0x8000000000 - 1)
 */
#define USER_VA_TOP             (UL(1) << (VA_BITS))

/*
 * 64G for each process's ASLR space
 */
#ifdef CONFIG_ASLR
#define USER_ASLR_SIZE          UL(0x1000000000)
#else
#define USER_ASLR_SIZE          UL(0x0000000000)
#endif

/* UserProcess(app) VMA space for REE mmeory - 64GB */
#define USER_VM4REE_SIZE        UL(0x1000000000)
#define USER_VM4REE_VA(p)       (USER_VA_TOP - USER_VM4REE_SIZE - \
								USER_ASLR_SIZE + (p)->aslr)

/* UserProcess(app) VMA space for TEE memory - 128GB */
#define USER_VM4TEE_SIZE        UL(0x2000000000)
#define USER_VM4TEE_VA(p)       (USER_VM4REE_VA(p) - USER_VM4TEE_SIZE)

/*
 * UserProcess(app) heap size (0 ~ 1G is reserved)
 * At least (512G - 64G - 64G - 128G - 1G) = 255G
 */
#define USER_HEAP_SIZE          (USER_VA_TOP - USER_ASLR_SIZE - USER_VM4REE_SIZE \
								- USER_VM4TEE_SIZE - UL(0x40000000))
#define USER_HEAP_VA(p)         (UL(0x40000000) + (p)->aslr)

/*
 * Kernel virtual address space - 128G (vmalloc/iomap etc.)
 * e.g. 0xFFFFFFA0_00000000 ~ (0xFFFFFFC0_00000000 - 1)
 * phys_to_virt(0) -> means vma_start nexts to the lowest VA
 */
#define KERN_VMA_SIZE UL(0x2000000000)
#define _KERN_VMA_START ((unsigned long)phys_to_virt(0) - KERN_VMA_SIZE)
#define KERN_VMA_START (_KERN_VMA_START >= (-(UL(1) << (VA_BITS))) ? \
					_KERN_VMA_START : (-KERN_VMA_SIZE))
#endif
