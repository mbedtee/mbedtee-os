/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Dynamic loading the shared or executable objects
 */

#ifndef _ELF_LOAD_H
#define _ELF_LOAD_H

#include <list.h>
#include <stddef.h>
#include <stdbool.h>

#include <elf_types.h>

/*
 * Structure for describing a loaded
 * executable or shared object file
 */
struct elf_obj {
	Elf_Ehdr *hdr;
	Elf_Shdr *shdr;
	Elf_Phdr *phdr;
	Elf_Dyn *dynamic;
	char *shstr;

	/*
	 * distinguish the application or DSO type
	 * is_pie -> Dynamic 0x6ffffffb (FLAGS_1) Flags: PIE
	 * is_app -> hdr->e_type == ET_EXEC || is_pie
	 * is_dso -> hdr->e_type == ET_DYN && !is_pie
	 */
	bool is_pie;
	bool is_app;
	bool is_dso;
	uint8_t nrloads;

	/*
	 * Reference counter for the DSO
	 */
	int refc;
	int dynamic_size;
	int symnum;

	char *name;

	/*
	 * memory for elf object file LOADs
	 * based on the LOAD in the program header
	 */
	void *kva;
	size_t size; /* sum of the LOADs' size */
	Elf_Addr vbase; /* the p_vaddr of first LOAD segment */

	/*
	 * runtime address addend
	 * only for executable objects.
	 */
	void *l_addr;

	/*
	 * Dynamic symbols
	 */
	Elf_Sym *dynsym;
	char *dynstr;
	Elf_Word *hash;

	/*
	 * Local symbols.
	 * only for executable objects.
	 * used for get the local symbol offset.
	 */
	Elf_Sym *symtab;
	char *strtab;

	/*
	 * map information for LOAD segments
	 */
	struct list_head loads;

	/*
	 * dynamic dependences
	 */
	struct list_head needs;

	/*
	 * multi-dso support
	 */
	struct list_head node;

	/*
	 * list for mapping the dependent DSO
	 */
	struct list_head maps;
};

/*
 * Allocate the memory and do the loading
 * for an executable or shared object file
 */
struct elf_obj *elf_load(const char *objname);

/*
 * Free the memory for a loaded
 * executable or shared object file
 */
void elf_unload(struct elf_obj *obj);

#endif
