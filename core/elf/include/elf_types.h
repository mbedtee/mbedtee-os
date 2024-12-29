/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ELF32 or ELF64 types
 */

#ifndef _ELF_TYPES_H
#define _ELF_TYPES_H

#include <elf.h>
#include <generated/autoconf.h>

#ifdef CONFIG_64BIT
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Off Elf_Off;
typedef Elf64_Word Elf_Word;
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Rela Elf_Rela;
#define ELF_ST_TYPE ELF64_ST_TYPE
#define ELF_R_SYM ELF64_R_SYM
#define ELF_R_TYPE ELF64_R_TYPE
#else
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Off Elf_Off;
typedef Elf32_Word Elf_Word;
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Rela Elf_Rela;
#define ELF_ST_TYPE ELF32_ST_TYPE
#define ELF_R_SYM ELF32_R_SYM
#define ELF_R_TYPE ELF32_R_TYPE
#endif

#endif
