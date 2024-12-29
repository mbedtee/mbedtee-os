// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch64 Arch-Specific ELF operations
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
	[EI_CLASS] = ELFCLASS64, [EI_DATA] = ELFDATA2LSB,
	[EI_VERSION] = EV_CURRENT, [EI_OSABI] = ELFOSABI_SYSV,
	[EI_ABIVERSION] = 0
};

/*
 * Verify the ELF header
 */
int elf_verify_header(Elf64_Ehdr *hdr)
{
	unsigned char *e_ident = hdr->e_ident;

	if (hdr->e_machine != EM_AARCH64)
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
	Elf64_Ehdr *hdr = obj->hdr;
	const Elf64_Shdr *shdr = obj->shdr;
	Elf64_Sym *dynsym = obj->dynsym;
	const Elf64_Shdr *sh = NULL;
	size_t relnr = 0;
	Elf64_Sym *sym = NULL;
	int symndx = 0;
	int symtyp = 0;
	void **reloc_addr = NULL;

	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (sh->sh_type == SHT_RELA) {
			Elf64_Rela *rela = NULL;
			Elf64_Rela *relatab = NULL;

			relatab = obj->kva + sh->sh_addr;
			relnr = sh->sh_size / sizeof(Elf64_Rela);

			LMSG("%s %p relnr=%ld @ %s\n", obj->name, l_addr, (long)relnr,
					obj->shstr + sh->sh_name);

			for (rela = relatab; rela < relatab + relnr; rela++) {
				symndx = ELF64_R_SYM(rela->r_info);
				symtyp = ELF64_R_TYPE(rela->r_info);
				sym = &dynsym[symndx];

				reloc_addr = kva + rela->r_offset;
				switch (symtyp) {
				case R_AARCH64_RELATIVE:
					*reloc_addr += (Elf64_Addr)l_addr;
					break;
				case R_AARCH64_GLOB_DAT:
				case R_AARCH64_JUMP_SLOT:
					if ((sym->st_shndx == SHN_UNDEF) ||
						(sym->st_shndx >= hdr->e_shnum))
						*reloc_addr = elf_dynsym(obj,
								obj->dynstr + sym->st_name);
					else
						*reloc_addr = l_addr + sym->st_value;
					*reloc_addr += rela->r_addend;
					if (rela->r_addend)
						LMSG("addend %lx\n", rela->r_addend);
					break;
				case R_AARCH64_ABS32:
				case R_AARCH64_ABS64:
					*reloc_addr += (Elf64_Addr)l_addr + sym->st_value;
					*reloc_addr += rela->r_addend;
					break;
				case R_AARCH64_COPY:
					LMSG("R_AARCH64_COPY %lx\n", sym->st_size);
					memcpy(reloc_addr, obj->kva + sym->st_value, sym->st_size);
					break;
				default:
					EMSG("undefined symbol type %d\n", symtyp);
					return -EINVAL;
				}
			}
		}
/*
 *		else if (sh->sh_type == SHT_REL) {
			Elf64_Rel *rel = NULL;
			Elf64_Rel *reltab = NULL;

			reltab = obj->kva + sh->sh_addr;
			relnr = sh->sh_size / sizeof(Elf64_Rel);

			for (rel = reltab; rel < reltab + relnr; rel++) {
				symndx = ELF64_R_SYM(rel->r_info);
				symtyp = ELF64_R_TYPE(rel->r_info);
				sym = &dynsym[symndx];

				reloc_addr = kva + rel->r_offset;
				switch (symtyp) {
				case R_AARCH64_RELATIVE:
					*reloc_addr += (Elf64_Addr)l_addr;
					break;
				case R_AARCH64_GLOB_DAT:
				case R_AARCH64_JUMP_SLOT:
					if ((sym->st_shndx == SHN_UNDEF) ||
						(sym->st_shndx >= hdr->e_shnum))
						*reloc_addr = elf_dynsym(obj,
								obj->dynstr + sym->st_name);
					else
						*reloc_addr = l_addr + sym->st_value;
					break;
				case R_AARCH64_ABS32:
				case R_AARCH64_ABS64:
					*reloc_addr += (Elf64_Addr)l_addr + sym->st_value;
					break;
				case R_AARCH64_COPY:
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
