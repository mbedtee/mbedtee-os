// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 Arch-Specific ELF operations
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

	if (hdr->e_machine != EM_MIPS)
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
 * Get the .got addr
 */
static off_t elf_get_got_addr(struct elf_obj *obj)
{
	Elf32_Dyn *d = NULL, *dhdr = obj->dynamic;
	size_t d_nr = obj->dynamic_size / sizeof(Elf32_Dyn);

	for (d = dhdr; d < dhdr + d_nr; d++) {
		if (d->d_tag == DT_PLTGOT)
			return d->d_un.d_ptr;
	}

	return 0;
}

/*
 * Get the .got size
 */
static size_t elf_get_got_size(struct elf_obj *obj)
{
	Elf32_Addr addr = elf_get_got_addr(obj);
	Elf32_Shdr *shdr = obj->shdr, *sh = NULL;
	Elf32_Ehdr *hdr = obj->hdr;

	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (sh->sh_addr == addr)
			return sh->sh_size;
	}

	return 0;
}

/*
 * Get the number of local got entries
 */
static size_t elf_get_got_localno(struct elf_obj *obj)
{
	Elf32_Dyn *d = NULL, *dhdr = obj->dynamic;
	size_t d_nr = obj->dynamic_size / sizeof(Elf32_Dyn);

	for (d = dhdr; d < dhdr + d_nr; d++) {
		if (d->d_tag == DT_MIPS_LOCAL_GOTNO)
			return d->d_un.d_val;
	}

	return 0;
}

/*
 * Get first dynamic symbol table entry that
 * corresponds to an entry in the GOT
 */
static size_t elf_get_got_symno(struct elf_obj *obj)
{
	Elf32_Dyn *d = NULL, *dhdr = obj->dynamic;
	size_t d_nr = obj->dynamic_size / sizeof(Elf32_Dyn);

	for (d = dhdr; d < dhdr + d_nr; d++) {
		if (d->d_tag == DT_MIPS_GOTSYM)
			return d->d_un.d_val;
	}

	return 0;
}

static int elf_relocate_sym(struct elf_obj *obj,
	void *l_addr, void *kva, Elf32_Rel *rel, Elf32_Addr *got,
	Elf32_Word gotsymno, Elf32_Word gotlocalnr)
{
	int symndx = 0, symtyp = 0;
	Elf32_Sym *sym = NULL;
	void **reloc_addr = NULL;

	symndx = ELF32_R_SYM(rel->r_info);
	symtyp = ELF32_R_TYPE(rel->r_info);
	sym = &obj->dynsym[symndx];

	reloc_addr = kva + rel->r_offset;

	switch (symtyp) {
	case R_MIPS_NONE:
		FMSG("%s symndx %d\n", obj->name, symndx);
		break;
	/*
	 * R_MIPS_REL32: A - EA + S
	 * The value EA used by the dynamic linker to relocate an R_MIPS_REL32
	 * relocation depends on its r_symndx value. If the relocation entry r_symndx is less
	 * than DT_MIPS_GOTSYM, the value of EA is the symbol st_value plus displacement.
	 * Otherwise, the value of EA is the value in the GOT entry corresponding to the
	 * relocation entry r_symndx.
	 *
	 * A:  Represents the addend used to compute the value of the relocatable field.
	 * EA: Represents the effective address of the symbol prior to relocation.
	 *
	 * S:  Represents the value of the symbol whose index resides in the relocation
	 * entry, unless the symbol is STB_LOCAL and is of type STT_SECTION in which
	 * case S represents the original sh_addr minus the final sh_addr.
	 */
	case R_MIPS_REL32:
		if (symndx == 0) {
			*reloc_addr += (Elf32_Addr)l_addr;
			break;
		}

		if (symndx < gotsymno) {
			if ((sym->st_info == STT_SECTION) &&
				(ELF32_ST_BIND(rel->r_info) == STB_LOCAL))
				*reloc_addr += (Elf32_Addr)l_addr;
			else {
				*reloc_addr += (Elf32_Addr)l_addr + sym->st_value;
			}
		} else {
			/* for toolchain elf32-littlemips, differ from elf32-tradlittlemips */
			if ((Elf32_Addr)*reloc_addr >= sym->st_value)
				*reloc_addr -= sym->st_value;

			*reloc_addr += got[symndx + gotlocalnr - gotsymno];
		}

		break;

	default:
		EMSG("undefined reloc = %p, %x\n", reloc_addr, symtyp);
		return -EINVAL;
	}

	return 0;
}

/*
 * relocate the shared or executable object to l_addr
 * kva is process's own mapping of the obj LOAD which contains .got and .data.rel.ro
 */
int elf_relocate(struct elf_obj *obj, void *l_addr, void *kva)
{
	int ret = 0;
	const Elf32_Shdr *sh = NULL;
	Elf32_Rel *rel = NULL;
	Elf32_Rel *reltab = NULL;
	size_t relnr = 0;
	Elf32_Ehdr *hdr = obj->hdr;
	const Elf32_Shdr *shdr = obj->shdr;
	Elf32_Sym *dynsym = obj->dynsym;
	Elf32_Word gotlocalnr = elf_get_got_localno(obj);
	Elf32_Addr *got = kva + elf_get_got_addr(obj);
	Elf32_Word gotsymno = elf_get_got_symno(obj), i = 2;
	Elf32_Word gotnr = elf_get_got_size(obj) / sizeof(Elf32_Addr);
	Elf32_Sym *sym = &dynsym[gotsymno];

	/*
	 * relocate the .got
	 */
	while (i < gotlocalnr)
		got[i++] += (Elf32_Addr)l_addr;
	while (i < gotnr) {
		if (sym->st_shndx == SHN_UNDEF)
			got[i++] = (Elf32_Addr)elf_dynsym(obj,
					obj->dynstr + sym->st_name);
		else
			got[i++] += (Elf32_Addr)l_addr;
		sym++;
	}

	/*
	 * relocate the .data.rel.ro
	 */
	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (sh->sh_type == SHT_REL) {
			reltab = obj->kva + sh->sh_addr;
			relnr = sh->sh_size / sizeof(Elf32_Rel);

			LMSG("%s %p relnr=%ld @ %s\n", obj->name, l_addr, (long)relnr,
					obj->shstr + sh->sh_name);

			for (rel = reltab; rel < reltab + relnr; rel++) {
				ret = elf_relocate_sym(obj, l_addr, kva, rel,
							got, gotsymno, gotlocalnr);
				if (ret != 0)
					return ret;
			}
		}
	}

	return 0;
}
