/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * common MMU definitions
 */

#ifndef _MMU_H
#define _MMU_H

#include <map.h>

#ifndef __ASSEMBLY__

#include <mem.h>
#include <init.h>
#include <list.h>
#include <stddef.h>
#include <spinlock.h>

struct process;

/*
 * page table struct
 */
struct pt_struct {
	/* page table directories */
	void *ptds;
	/* pt lock */
	struct spinlock lock;
	/* Address Space ID */
	unsigned short asid;

	/* @ which process */
	struct process *proc;

	/*
	 * for AArch32@ARMV7-A / RISCV-Sv32-Sv39 only
	 *
	 * reference counter of each ptd,
	 * each ptd has (#PTES_PER_PTD) PTEs
	 */
	void *refc;
};

/*
 * Map the @pa to @va under @pt
 */
int map(struct pt_struct *pt, unsigned long pa, void *va,
			unsigned long size, unsigned long flags);

/*
 * Unmap the @va under @pt
 */
void unmap(struct pt_struct *pt, void *va, unsigned long size);

/*
 * access ok() checks if the user
 * address range is accessible or not
 * according to the expected access flags
 */
int access_user_ok(const void *addr, size_t size, int prot);

/*
 * access ok() checks if the kernel
 * address range is accessible or not
 * according to the expected access flags
 */
int access_kern_ok(const void *addr, size_t size, int prot);

/*
 * Convert the userspace address to physical address
 * Workable only on: conversion for current process
 */
unsigned long user_virt_to_phys(void *va);
/*
 * slowpath of user_virt_to_phys()
 * Workable for current and other processes, but the most
 * possibly scenario is: conversion for other process
 */
unsigned long user_virt_to_phys_pt(
	struct pt_struct *pt, void *va);

/*
 * alloc user page table
 */
int alloc_pt(struct process *proc);

/*
 * free user page table
 */
void free_pt(struct pt_struct *pt);

/*
 * Size of 1 MMU Section or Superpage.
 */
unsigned long mmu_section_size(void);

/*
 * setup page table for early init
 */
int __init map_early(unsigned long pa,	size_t size, unsigned long flags);

/*
 * setup and enable the MMU
 */
void __init mmu_init(void);

void __init mmu_init_kpt(struct pt_struct *pt);

#endif
#endif
