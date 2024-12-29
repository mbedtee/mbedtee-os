/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Process related ELF functions
 */

#ifndef _ELF_PROC_H
#define _ELF_PROC_H

/*
 * loading for a process ELF
 */
int elf_load_proc(struct process *proc);

/*
 * unloading for a process ELF
 */
void elf_unload_proc(struct process *proc);

/*
 * for backtrace purpose
 *
 * Get the function name based on the function run addr.
 *
 * To use this function, the .symtab and .strtab must be present in ELF.
 * Note that: "strip -s or strip --strip-unneeded" removes these
 * two sections,  thus Programmer shall use "strip --strip-debug"
 * to keep them in ELF.
 */
const char *elf_proc_funcname(struct process *proc, unsigned long runaddr,
	unsigned long *offset);

#endif
