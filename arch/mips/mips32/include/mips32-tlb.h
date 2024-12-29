/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 TLB maintenance
 */

#ifndef _MIPS32_TLB_H
#define _MIPS32_TLB_H

#include <mmu.h>

/*
 * walks the page table and refills
 * a TLB entry that matches the
 * va in this given page table
 * prot: permission flag
 */
int tlb_refill(struct pt_struct *pt, unsigned long va, int prot);

void tlb_invalidate_all(void);

#endif
