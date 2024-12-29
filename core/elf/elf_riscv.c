// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV32/RISCV64 Arch-Specific ELF operations
 * symbol relocation, header verification etc.
 */

#include <errno.h>
#include <string.h>
#include <trace.h>

#include <elf_load.h>

#include "elf_priv.h"

/* relocations types */
#define R_RISCV_NONE       0
#define R_RISCV_32         1
#define R_RISCV_64         2
#define R_RISCV_RELATIVE   3
#define R_RISCV_COPY       4
#define R_RISCV_JUMP_SLOT  5

#if defined(CONFIG_64BIT)
#define ELFCLASS ELFCLASS64
#else
#define ELFCLASS ELFCLASS32
#endif

static const unsigned char __elf_ident[EI_NIDENT] = {
	[EI_MAG0] = ELFMAG0, [EI_MAG1] = ELFMAG1,
	[EI_MAG2] = ELFMAG2, [EI_MAG3] = ELFMAG3,
	[EI_CLASS] = ELFCLASS, [EI_DATA] = ELFDATA2LSB,
	[EI_VERSION] = EV_CURRENT, [EI_OSABI] = ELFOSABI_SYSV,
	[EI_ABIVERSION] = 0
};

/*
 * Verify the ELF header
 */
int elf_verify_header(Elf_Ehdr *hdr)
{
	unsigned char *e_ident = hdr->e_ident;

	if (hdr->e_machine != EM_RISCV)
		return -ENOTSUP;

	if (hdr->e_version != EV_CURRENT)
		return -ENOTSUP;

	if ((hdr->e_type != ET_EXEC) &&
		(hdr->e_type != ET_DYN))
		return -ENOTSUP;

	if (memcmp(&__elf_ident, e_ident, EI_ABIVERSION))
		return -ENOTSUP;

	return 0;
}

/*
 * relocate the shared or executable object to l_addr
 * kva is process's own mapping of the obj LOAD which
 * contains .got, .got.plt and .data.rel.ro
 */
int elf_relocate(struct elf_obj *obj, void *l_addr, void *kva)
{
	const Elf_Shdr *sh = NULL;
	size_t relnr = 0;
	int symndx = 0, symtyp = 0;
	void **reloc_addr = NULL;
	Elf_Sym *sym = NULL;
	Elf_Ehdr *hdr = obj->hdr;
	const Elf_Shdr *shdr = obj->shdr;
	Elf_Sym *dynsym = obj->dynsym;

	/*
	 * relocate the .rela.dyn and .rela.plt
	 */
	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (sh->sh_type == SHT_RELA) {
			Elf_Rela *rela = NULL;
			Elf_Rela *relatab = NULL;

			relatab = obj->kva + sh->sh_offset;
			relnr = sh->sh_size / sizeof(Elf_Rela);

			LMSG("%s %p relnr=%ld @ %s\n", obj->name, l_addr, (long)relnr,
					obj->shstr + sh->sh_name);

			for (rela = relatab; rela < relatab + relnr; rela++) {
				symndx = ELF_R_SYM(rela->r_info);
				symtyp = ELF_R_TYPE(rela->r_info);
				sym = &dynsym[symndx];

				reloc_addr = kva + rela->r_offset;

				switch (symtyp) {
				case R_RISCV_RELATIVE:
					*reloc_addr = l_addr + rela->r_addend;
					break;
				case R_RISCV_32:
				case R_RISCV_64:
				case R_RISCV_JUMP_SLOT:
					if ((sym->st_shndx == SHN_UNDEF) ||
						(sym->st_shndx >= hdr->e_shnum))
						*reloc_addr = elf_dynsym(obj,
								obj->dynstr + sym->st_name) + rela->r_addend;
					else
						*reloc_addr = l_addr + sym->st_value + rela->r_addend;
					break;
				case R_RISCV_COPY:
					memcpy(reloc_addr, obj->kva + sym->st_value
						+ rela->r_addend, sym->st_size);
					break;
				case R_RISCV_NONE:
					break;
				default:
					EMSG("undefined symbol type %d\n", symtyp);
					return -EINVAL;
				}
			}
		}
	}

	return 0;
}
