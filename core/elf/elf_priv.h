/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ELF private definitions and functions
 */

#ifndef _ELF_PRIV_H
#define _ELF_PRIV_H

#include <list.h>
#include <stddef.h>
#include <stdbool.h>

#include <elf_types.h>

#define ELF_ALIGNED_LOAD_SIZE(l)					\
({													\
	Elf_Addr __align = l->align;					\
	Elf_Addr __start = (l)->addr & ~(__align - 1);	\
	Elf_Addr __end = (l)->addr + (l)->size;			\
	Elf_Addr __bias = __end & (__align - 1);		\
	if (__bias)										\
		__end += __align - __bias;					\
	(__end - __start);								\
})

/*
 * Structure for describing the mapping
 * informations of a LOAD segment
 */
struct elf_ld {
	struct list_head node;
	/*
	 * pages
	 */
	struct page **pages;
	/*
	 * load size
	 */
	int nr_pages;

	/*
	 * p_offset within the ELF file
	 */
	int offset;

	/*
	 * load address of p_offset
	 */
	Elf_Addr addr;

	/*
	 * end-boundary alignment
	 */
	int align;
	/*
	 * p_memsz
	 */
	int size;
	/*
	 * p_filesz
	 */
	int filesz;

	/*
	 * load mapping flag
	 */
	int flags;
	/*
	 * user space va mapped or not
	 */
	bool uva_mapped;
	/*
	 * kernel space va mapped or not
	 */
	bool kva_mapped;
};

/*
 * Structure for describing the dynamic
 * needed libraries (dependances)
 */
struct elf_needed {
	struct list_head node;
	struct elf_obj *obj;
};

/*
 * Verify the ELF header
 */
int elf_verify_header(Elf_Ehdr *hdr);

/*
 * Get the dynamic symbol run address according to the
 * specified dynamic symbol name.
 */
void *elf_dynsym(struct elf_obj *obj, const char *name);

/*
 * relocate the shared or executable object
 */
int elf_relocate(struct elf_obj *obj, void *l_addr, void *reloc);

#endif
