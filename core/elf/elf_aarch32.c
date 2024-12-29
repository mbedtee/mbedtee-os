// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32@ARMV7-A Arch-Specific ELF operations
 * symbol relocation, header verification etc.
 */

#include <errno.h>
#include <string.h>
#include <trace.h>

#include <elf_load.h>

#include "elf_priv.h"

static const unsigned char __elf_ident[EI_NIDENT] = {
	[EI_MAG0] = ELFMAG0, [EI_MAG1] = ELFMAG1,
	[EI_MAG2] = ELFMAG2, [EI_MAG3] = ELFMAG3,
	[EI_CLASS] = ELFCLASS32, [EI_DATA] = ELFDATA2LSB,
	[EI_VERSION] = EV_CURRENT, [EI_OSABI] = ELFOSABI_SYSV,
	[EI_ABIVERSION] = 0
};

/*
 * Verify the ELF header
 */
int elf_verify_header(Elf32_Ehdr *hdr)
{
	unsigned char *e_ident = hdr->e_ident;

	if (hdr->e_machine != EM_ARM)
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
 * kva is process's own mapping of the obj LOAD which contains .got and .data.rel.ro
 */
int elf_relocate(struct elf_obj *obj, void *l_addr, void *kva)
{
	Elf32_Ehdr *hdr = obj->hdr;
	const Elf32_Shdr *shdr = obj->shdr;
	Elf32_Sym *dynsym = obj->dynsym;
	const Elf32_Shdr *sh = NULL;
	size_t relnr = 0;
	Elf32_Sym *sym = NULL;
	int symndx = 0;
	int symtyp = 0;
	void **reloc_addr = NULL;

	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (sh->sh_type == SHT_REL) {
			Elf32_Rel *rel = NULL;
			Elf32_Rel *reltab = NULL;

			reltab = obj->kva + sh->sh_addr;
			relnr = sh->sh_size / sizeof(Elf32_Rel);

			LMSG("%s %p relnr=%ld @ %s\n", obj->name, l_addr, (long)relnr,
					obj->shstr + sh->sh_name);

			for (rel = reltab; rel < reltab + relnr; rel++) {
				symndx = ELF32_R_SYM(rel->r_info);
				symtyp = ELF32_R_TYPE(rel->r_info);
				sym = &dynsym[symndx];

				reloc_addr = kva + rel->r_offset;
				switch (symtyp) {
				case R_ARM_RELATIVE:
					*reloc_addr += (Elf32_Addr)l_addr;
					break;
				case R_ARM_GLOB_DAT:
				case R_ARM_JUMP_SLOT:
					if ((sym->st_shndx == SHN_UNDEF) ||
						(sym->st_shndx >= hdr->e_shnum))
						*reloc_addr = elf_dynsym(obj,
								obj->dynstr + sym->st_name);
					else
						*reloc_addr = l_addr + sym->st_value;
					break;
				case R_ARM_ABS32:
					*reloc_addr += (Elf32_Addr)l_addr + sym->st_value;
					break;
				case R_ARM_COPY:
					memcpy(reloc_addr, obj->kva + sym->st_value, sym->st_size);
					break;
				default:
					EMSG("undefined symbol type %d\n", symtyp);
					return -EINVAL;
				}
			}
		}
/*
 *		else if (sh->sh_type == SHT_RELA) {
			Elf32_Rela *rela = NULL;
			Elf32_Rela *relatab = NULL;

			relatab = obj->kva + sh->sh_offset;
			relnr = sh->sh_size / sizeof(Elf32_Rela);

			for (rela = relatab; rela < relatab + relnr; rela++) {
				symndx = ELF32_R_SYM(rela->r_info);
				symtyp = ELF32_R_TYPE(rela->r_info);
				sym = &dynsym[symndx];

				reloc_addr = kva + rela->r_offset;
				switch (symtyp) {
				case R_ARM_RELATIVE:
					*reloc_addr += (Elf32_Addr)l_addr + rela->r_addend;
					break;
				case R_ARM_GLOB_DAT:
				case R_ARM_JUMP_SLOT:
					if ((sym->st_shndx == SHN_UNDEF) ||
						(sym->st_shndx >= hdr->e_shnum))
						*reloc_addr = elf_dynsym(obj,
								obj->dynstr + sym->st_name) + rela->r_addend;
					else
						*reloc_addr = l_addr + sym->st_value + rela->r_addend;
					break;
				case R_ARM_ABS32:
					*reloc_addr += (Elf32_Addr)l_addr + sym->st_value + rela->r_addend;
					break;
				case R_ARM_COPY:
					memcpy(reloc_addr, obj->kva + sym->st_value, sym->st_size);
					break;
				default:
					EMSG("undefined symbol type %d\n", symtyp);
					return -EINVAL;
				}
			}
		}
*/
	}

	return 0;
}
