// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ELF - Dynamic loading the shared or executable objects
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>

#include <trace.h>
#include <mmu.h>
#include <sched.h>
#include <file.h>
#include <timer.h>
#include <vma.h>
#include <kvma.h>
#include <kproc.h>
#include <kmalloc.h>
#include <vmalloc.h>
#include <page_scatter.h>
#include <elf_load.h>

#include "elf_priv.h"

/*
 * Loaded dynamic shared objects list
 */
static LIST_HEAD(dsolist);
static SPIN_LOCK(dsolock);

static int elf_alloc_header(struct elf_obj *obj)
{
	obj->hdr = kmalloc(sizeof(Elf_Ehdr));

	return obj->hdr ? 0 : -ENOMEM;
}

static void elf_free_header(struct elf_obj *obj)
{
	kfree(obj->hdr);
}

static int elf_read_header(struct elf_obj *obj, int fd)
{
	ssize_t ret = 0;
	Elf_Word size = sizeof(Elf_Ehdr);

	sys_lseek(fd, 0, SEEK_SET);
	ret = sys_read(fd, obj->hdr, size);
	if (size != ret) {
		EMSG("Error while reading hdr %d %d\n", (int)size, (int)ret);
		return -ENOENT;
	}

	return 0;
}

static void elf_check_type(struct elf_obj *obj)
{
#define	DF_1_PIE 0x08000000

	Elf_Dyn *d = NULL, *dhdr = obj->dynamic;
	size_t d_nr = obj->dynamic_size / sizeof(Elf_Dyn);

	/* check .dynamic to if it has the PIE flag */
	for (d = dhdr + d_nr - 1; d >= dhdr; d--) {
		if (d->d_tag == DT_FLAGS_1 &&
			d->d_un.d_val == DF_1_PIE) {
			obj->is_pie = true;
			break;
		}
	}
	obj->is_app = (obj->hdr->e_type == ET_EXEC) || obj->is_pie;
	obj->is_dso = (obj->hdr->e_type == ET_DYN) && !obj->is_pie;
}

/*
 * Get .dynstr section offset
 */
static off_t elf_get_dynstr_off(struct elf_obj *obj)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	Elf_Shdr *sh = NULL;

	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (sh->sh_type == SHT_STRTAB) {
			obj->dynstr = obj->kva + sh->sh_addr;
			return sh->sh_addr;
		}
	}

	return -ENOENT;
}

/*
 * Get .dynsym section offset
 */
static off_t elf_get_dynsym_off(struct elf_obj *obj)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	Elf_Shdr *sh = NULL;

	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (sh->sh_type == SHT_DYNSYM) {
			obj->dynsym = obj->kva + sh->sh_addr;
			return sh->sh_addr;
		}
	}

	return -ENOENT;
}

/*
 * Free the resources of the LOAD segments
 */
static void elf_free_load(struct elf_obj *obj)
{
	struct elf_ld *load = NULL, *n = NULL;

	list_for_each_entry_safe(load, n, &obj->loads, node) {
		list_del(&load->node);
		if (load->kva_mapped) {
			pages_sc_unmap(load->pages, kpt(), obj->kva +
				rounddown(load->addr, load->align), load->nr_pages);
		}
		pages_sc_free(load->pages, load->nr_pages);
		kfree(load);
	}
}

/*
 * Alloc the resources for the LOAD segments
 */
static int elf_alloc_load(struct elf_obj *obj)
{
	int ret = -ENOMEM;
	Elf_Phdr *ph = NULL;
	Elf_Phdr *phdr = obj->phdr;
	Elf_Word nr_ph = obj->hdr->e_phnum;
	struct elf_ld *load = NULL;
	size_t size = 0;

	for (ph = phdr; ph < phdr + nr_ph; ph++) {
		if (ph->p_type == PT_LOAD) {
			if ((ph->p_align < PAGE_SIZE) ||
				(ph->p_align & (PAGE_SIZE - 1))) {
				ret = -EFTYPE;
				goto out;
			}

			load = kmalloc(sizeof(struct elf_ld));
			if (!load)
				goto out;

			if (!obj->size)
				obj->vbase = ph->p_vaddr;

			load->flags = 0;
			load->uva_mapped = false;
			load->kva_mapped = false;
			load->addr = ph->p_vaddr;
			load->size = ph->p_memsz;
			load->filesz = ph->p_filesz;
			load->offset = ph->p_offset;
			load->align = ph->p_align;

			size = ELF_ALIGNED_LOAD_SIZE(load);

			load->nr_pages = size >> PAGE_SHIFT;

			LMSG("p_offset %lx, p_vaddr %lx, p_memsz %lx, allocsize %lx, align %lx\n",
				(long)ph->p_offset, (long)ph->p_vaddr,
				(long)ph->p_memsz, (long)size, (long)ph->p_align);

			load->pages = pages_sc_alloc(load->nr_pages);
			if (!load->pages) {
				kfree(load);
				goto out;
			}

			if (ph->p_flags & PF_R)
				load->flags |= PG_RO;
			if (ph->p_flags & PF_W)
				load->flags |= PG_RW;
			if (ph->p_flags & PF_X)
				load->flags |= PG_EXEC;

			list_add_tail(&load->node, &obj->loads);
			obj->size += size;
			obj->nrloads += 1;
		}
	}

	if (obj->size >= mem_size) {
		ret = -ENOTSUP;
		goto out;
	}

	return 0;

out:
	return ret;
}

/*
 * Read the LOAD from file to memory
 */
static int elf_read_load(struct elf_obj *obj, int fd)
{
	int ret = -1;
	Elf_Off bias = 0;
	size_t read_sz = 0;
	struct elf_ld *load = NULL;
	Elf_Addr vaddr = 0;

	list_for_each_entry(load, &obj->loads, node) {
		/*
		 * map to kernel firstly, RW
		 */
		ret = pages_sc_map(load->pages, kpt(), obj->kva +
			 rounddown(load->addr, load->align), load->nr_pages, PG_RW);
		if (ret != 0)
			return ret;

		load->kva_mapped = true;

		/*
		 * Reading...
		 */
		vaddr = load->addr;

		/* clean the bias in the header */
		bias = vaddr % load->align;
		if (bias != 0)
			memset(obj->kva + vaddr - bias, 0, bias);

		/* clean the bias in the tail */
		bias = (vaddr + load->size) % load->align;
		if (bias != 0)
			memset(obj->kva + vaddr + load->size, 0, load->align - bias);

		/* clean the .bss */
		bias = load->size - load->filesz;
		if (bias != 0)
			memset(obj->kva + vaddr + load->filesz, 0, bias);

		sys_lseek(fd, load->offset, SEEK_SET);
		read_sz = sys_read(fd, obj->kva + vaddr, load->filesz);
		if (read_sz != load->filesz) {
			EMSG("Error reading LOAD\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int elf_alloc_kva(struct elf_obj *obj)
{
	/* allocate KVA */
	obj->kva = kvma_alloc(obj->size);
	if (obj->kva == NULL)
		return -ENOMEM;

	obj->kva -= obj->vbase;

	return 0;
}

static void elf_free_kva(struct elf_obj *obj)
{
	if (obj->kva) {
		kvma_free(obj->kva + obj->vbase);
		obj->kva = NULL;
	}
}

static int elf_alloc_ph(struct elf_obj *obj)
{
	obj->phdr = kmalloc(obj->hdr->e_phnum * sizeof(Elf_Phdr));

	return obj->phdr ? 0 : -ENOMEM;
}

static void elf_free_ph(struct elf_obj *obj)
{
	kfree(obj->phdr);
}

static int elf_read_ph(struct elf_obj *obj, int fd)
{
	size_t size = obj->hdr->e_phnum * sizeof(Elf_Phdr);

	sys_lseek(fd, obj->hdr->e_phoff, SEEK_SET);
	if (size != sys_read(fd, obj->phdr, size)) {
		EMSG("Error while reading phdr\n");
		return -ENOENT;
	}

	return 0;
}

static int elf_alloc_sh(struct elf_obj *obj)
{
	obj->shdr = kmalloc(obj->hdr->e_shnum * sizeof(Elf_Shdr));

	return obj->shdr ? 0 : -ENOMEM;
}

static void elf_free_sh(struct elf_obj *obj)
{
	kfree(obj->shdr);
}

static int elf_read_sh(struct elf_obj *obj, int fd)
{
	size_t size = obj->hdr->e_shnum * sizeof(Elf_Shdr);

	sys_lseek(fd, obj->hdr->e_shoff, SEEK_SET);
	if (size != sys_read(fd, obj->shdr, size)) {
		EMSG("Error while reading shdr\n");
		return -ENOENT;
	}

	return 0;
}

/*
 * Get .dynamic size.
 */
static size_t elf_get_dynamic_size(struct elf_obj *obj)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	Elf_Shdr *sh = NULL;
/*
 *	Elf_Phdr *phdr = obj->phdr;
 *	Elf_Phdr *ph = NULL;
 *	for (ph = phdr; ph < phdr + hdr->e_phnum; ph++) {
 *		if (ph->p_type == PT_DYNAMIC) {
 *			obj->dynamic_size = ph->p_memsz;
 *			return ph->p_memsz;
 *		}
 *	}
 */

	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (sh->sh_type == SHT_DYNAMIC) {
			obj->dynamic_size = sh->sh_size;
			return sh->sh_size;
		}
	}
	return 0;
}

/*
 * Get .dynamic offset in ELF file.
 */
static off_t elf_get_dynamic_offset(struct elf_obj *obj)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Phdr *phdr = obj->phdr;
	Elf_Phdr *ph = NULL;

	for (ph = phdr; ph < phdr + hdr->e_phnum; ph++) {
		if (ph->p_type == PT_DYNAMIC)
			return ph->p_offset;
	}

	return -ENOENT;
}

static int elf_alloc_dynamic(struct elf_obj *obj)
{
	obj->dynamic = kmalloc(elf_get_dynamic_size(obj));

	return obj->dynamic ? 0 : -ENOMEM;
}

static void elf_free_dynamic(struct elf_obj *obj)
{
	kfree(obj->dynamic);
}

static int elf_read_dynamic(struct elf_obj *obj, int fd)
{
	size_t size = elf_get_dynamic_size(obj);

	sys_lseek(fd, elf_get_dynamic_offset(obj), SEEK_SET);
	if (size != sys_read(fd, obj->dynamic, size)) {
		EMSG("Error while reading shdr\n");
		return -ENOENT;
	}

	return 0;
}

static int elf_alloc_shstr(struct elf_obj *obj)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	char *shstr = kmalloc(shdr[hdr->e_shstrndx].sh_size);

	obj->shstr = shstr;

	return shstr ? 0 : -ENOMEM;
}

static void elf_free_shstr(struct elf_obj *obj)
{
	kfree(obj->shstr);
}

static int elf_read_shstr(struct elf_obj *obj, int fd)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	size_t size = shdr[hdr->e_shstrndx].sh_size;

	sys_lseek(fd, shdr[hdr->e_shstrndx].sh_offset, SEEK_SET);
	if (size != sys_read(fd, obj->shstr, size)) {
		EMSG("Error while reading shstr\n");
		return -ENOENT;
	}

	return 0;
}

static int elf_alloc_strtab(struct elf_obj *obj, int fd)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	Elf_Shdr *sh = NULL;
	off_t offset = 0;
	size_t size = 0;

	for (sh = shdr + hdr->e_shnum - 1; sh >= shdr; sh--) {
		if ((sh->sh_type == SHT_STRTAB) &&
			(sh != &shdr[hdr->e_shstrndx])) {
			offset = sh->sh_offset;
			size = sh->sh_size;
			break;
		}
	}

	if (!size) {
		EMSG("Error no strtab\n");
		return -ENOENT;
	}

	obj->strtab = vmalloc(size);
	if (obj->strtab == NULL) {
		EMSG("alloc strtab failed - 0x%lx\n", (long)size);
		return -ENOMEM;
	}

	sys_lseek(fd, offset, SEEK_SET);
	if (size != sys_read(fd, obj->strtab, size))
		return -ENOENT;

	return 0;
}

static void elf_free_strtab(struct elf_obj *obj)
{
	vfree(obj->strtab);
}

static int elf_alloc_symtab(struct elf_obj *obj, int fd)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	Elf_Shdr *sh = NULL;
	off_t offset = 0;
	size_t size = 0;

	for (sh = shdr + hdr->e_shnum - 1; sh >= shdr; sh--) {
		if (sh->sh_type == SHT_SYMTAB) {
			offset = sh->sh_offset;
			size = sh->sh_size;
			break;
		}
	}

	if (!size) {
		EMSG("Error no symtab\n");
		return -ENOENT;
	}

	obj->symnum = size / sizeof(Elf_Sym);

	obj->symtab = vmalloc(size);
	if (obj->symtab == NULL) {
		EMSG("alloc symtab failed - 0x%lx\n", (long)size);
		return -ENOMEM;
	}

	sys_lseek(fd, offset, SEEK_SET);
	if (size != sys_read(fd, obj->symtab, size))
		return -ENOENT;

	return 0;
}

static void elf_free_symtab(struct elf_obj *obj)
{
	vfree(obj->symtab);
}

/*
 * Get HASH offset
 */
static off_t elf_get_hash_off(struct elf_obj *obj)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	Elf_Shdr *sh = NULL;

	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (sh->sh_type == SHT_HASH) {
			obj->hash = obj->kva + sh->sh_addr;
			return sh->sh_addr;
		}
	}

	return -ENOENT;
}

static void elf_info(struct elf_obj *obj)
{
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	char *shstr = obj->shstr;
	Elf_Shdr *s = NULL;

	LMSG("Addr\t\tOff\tSize\tType\t\tName\n");
	for (s = shdr; s < shdr + hdr->e_shnum; s++) {
		LMSG("%08lX\t%06lX\t%06lX\t%08lX\t%s\n", (long)s->sh_addr,
			(long)s->sh_offset, (long)s->sh_size,
			(long)s->sh_type, shstr + s->sh_name);
	}
}

static int elf_open(const char *objname)
{
	int fd = -1;
	char *slash = NULL;
	char dsopath[128];

	if (!objname)
		return fd;

	LMSG("opening %s\n", objname);

	fd = sys_open(objname, O_RDONLY);
	if (fd < 0) {
		if (strstr(objname, ".so")) {
			slash = strrchr(objname, '/');
			objname = slash ? slash + 1 : objname;
			snprintf(dsopath, sizeof(dsopath), "/lib/%s", objname);
			fd = sys_open(dsopath, O_RDONLY);
			if (fd < 0) {
				snprintf(dsopath, sizeof(dsopath), "/user/lib/%s", objname);
				fd = sys_open(dsopath, O_RDONLY);
			}
		}
	}

	return fd;
}

static void elf_free(struct elf_obj *obj)
{
	if (obj) {
		elf_free_header(obj);
		elf_free_ph(obj);
		elf_free_sh(obj);
		elf_free_dynamic(obj);
		elf_free_shstr(obj);
		elf_free_load(obj);

		elf_free_symtab(obj);
		elf_free_strtab(obj);
		elf_free_kva(obj);
		kfree(obj->name);
		kfree(obj);
	}
}

static struct elf_obj *elf_alloc(const char *objname)
{
	int ret = -1;
	int fd = -1, name_l = 0;
	struct elf_obj *obj = NULL;
	char *slash = NULL;

	fd = elf_open(objname);
	if (fd < 0) {
		EMSG("Error while trying to sys_open %s %d\n", objname, fd);
		return NULL;
	}

	obj = kzalloc(sizeof(struct elf_obj));
	if (!obj)
		goto out;

	INIT_LIST_HEAD(&obj->needs);
	INIT_LIST_HEAD(&obj->loads);
	INIT_LIST_HEAD(&obj->node);
	INIT_LIST_HEAD(&obj->maps);
	obj->refc = 1;

	ret = elf_alloc_header(obj);
	if (ret != 0) {
		EMSG("alloc header failed\n");
		goto out;
	}

	ret = elf_read_header(obj, fd);
	if (ret != 0)
		goto out;

	ret = elf_verify_header(obj->hdr);
	if (ret != 0) {
		EMSG("elf_verify_header failed\n");
		goto out;
	}

	ret = elf_alloc_ph(obj);
	if (ret != 0) {
		EMSG("alloc ph failed\n");
		goto out;
	}

	ret = elf_read_ph(obj, fd);
	if (ret != 0)
		goto out;

	ret = elf_alloc_sh(obj);
	if (ret != 0) {
		EMSG("alloc sh failed\n");
		goto out;
	}

	ret = elf_read_sh(obj, fd);
	if (ret != 0)
		goto out;

	ret = elf_alloc_dynamic(obj);
	if (ret != 0) {
		EMSG("alloc .dynamic failed\n");
		goto out;
	}

	ret = elf_read_dynamic(obj, fd);
	if (ret != 0)
		goto out;

	elf_check_type(obj);

	ret = elf_alloc_shstr(obj);
	if (ret != 0) {
		EMSG("alloc .shstrtab failed\n");
		goto out;
	}

	ret = elf_read_shstr(obj, fd);
	if (ret != 0)
		goto out;

	ret = elf_alloc_load(obj);
	if (ret != 0) {
		EMSG("alloc load failed\n");
		goto out;
	}

	ret = elf_alloc_kva(obj);
	if (ret < 0) {
		EMSG("alloc kva or l_addr failed\n");
		goto out;
	}

	ret = elf_read_load(obj, fd);
	if (ret != 0)
		goto out;

	ret = elf_get_dynstr_off(obj);
	if (ret < 0) {
		EMSG("no .dynstr\n");
		goto out;
	}

	ret = elf_get_dynsym_off(obj);
	if (ret < 0) {
		EMSG("no .dynsym\n");
		goto out;
	}

	ret = elf_get_hash_off(obj);
	if (ret < 0) {
		EMSG("no .hash\n");
		goto out;
	}

	/* the .symtab and .strtab is necessary for app */
	ret = elf_alloc_symtab(obj, fd);
	if ((ret < 0) && obj->is_app)
		goto out;
	ret = elf_alloc_strtab(obj, fd);
	if ((ret < 0) && obj->is_app)
		goto out;

	/*
	 * show the section information
	 */
	elf_info(obj);

	if (obj->is_dso) {
		slash = strrchr(objname, '/');
		objname = slash ? slash + 1 : objname;
	}
	name_l = strlen(objname) + 1;
	obj->name = kmalloc(name_l);
	if (obj->name == NULL)
		goto out;
	strlcpy(obj->name, objname, name_l);

	sys_close(fd);
	return obj;

out:
	elf_free(obj);
	sys_close(fd);
	return NULL;
}

static void elf_put(struct elf_obj *obj)
{
	elf_unload(obj);
}

static struct elf_obj *elf_match(const char *objname)
{
	struct elf_obj *obj = NULL;

	list_for_each_entry(obj, &dsolist, node) {
		if (!strcmp(objname, obj->name))
			return obj;
	}
	return NULL;
}

static struct elf_obj *elf_get(const char *objname)
{
	struct elf_obj *obj = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&dsolock, flags);

	obj = elf_match(objname);
	if (obj != NULL)
		obj->refc++;

	spin_unlock_irqrestore(&dsolock, flags);

	return obj;
}

/*
 * Put the NEEDED dynamic shared library
 */
static void elf_put_needed(struct elf_obj *obj)
{
	struct elf_needed *needed = NULL, *n = NULL;

	list_for_each_entry_safe(needed, n, &obj->needs, node) {
		elf_put(needed->obj);
		list_del(&needed->node);
		kfree(needed);
	}
}

/*
 * Get the NEEDED dynamic shared library
 */
static int elf_get_needed(struct elf_obj *obj)
{
	const char *objname = NULL;
	int ret = -1;
	char *slash = NULL;
	struct elf_needed *needed = NULL;
	struct elf_obj *dso = NULL;
	Elf_Dyn *d = NULL, *dhdr = obj->dynamic;
	size_t d_nr = obj->dynamic_size / sizeof(Elf_Dyn);

	for (d = dhdr; d < dhdr + d_nr; d++) {
		LMSG("d_tag %ld val %lx\n", (long)d->d_tag, (long)d->d_un.d_val);

		if (d->d_tag == DT_NEEDED) {
			objname = obj->dynstr + d->d_un.d_val;
			slash = strrchr(objname, '/');
			objname = slash ? slash + 1 : objname;
			LMSG("%s needs %s\n", obj->name, objname);
			if (strlen(objname) == 0)
				continue;
			dso = elf_get(objname);
			if (dso == NULL)
				dso = elf_load(objname);

			if (dso == NULL)
				dso = elf_get(objname);
			if (dso == NULL) {
				ret = -ENOENT;
				goto out;
			}

			needed = kmalloc(sizeof(struct elf_needed));
			if (!needed) {
				elf_put(dso);
				ret = -ENOMEM;
				goto out;
			}

			needed->obj = dso;
			list_add_tail(&needed->node, &obj->needs);
		} else if (d->d_tag == DT_NULL)
			break;
	}

	ret = 0;

out:
	if (ret)
		elf_put_needed(obj);
	return ret;
}

struct elf_obj *elf_load(const char *objname)
{
	int ret = -1;
	unsigned long flags = 0;

	struct elf_obj *obj = elf_alloc(objname);

	if (!obj)
		return NULL;

	ret = elf_get_needed(obj);
	if (ret != 0)
		goto out;

	if (obj->is_dso) {
		spin_lock_irqsave(&dsolock, flags);
		if (elf_match(objname) == NULL) {
			list_add_tail(&obj->node, &dsolist);
			spin_unlock_irqrestore(&dsolock, flags);
		} else {
			spin_unlock_irqrestore(&dsolock, flags);
			goto out;
		}
	}

	return obj;

out:
	elf_put_needed(obj);
	elf_free(obj);
	return NULL;
}

void elf_unload(struct elf_obj *obj)
{
	unsigned long flags = 0;

	if (obj) {
		spin_lock_irqsave(&dsolock, flags);
		assert(obj->refc >= 1);
		obj->refc--;
		if (obj->refc == 0) {
			list_del(&obj->node);
			spin_unlock_irqrestore(&dsolock, flags);
			elf_put_needed(obj);
			elf_free(obj);
		} else
			spin_unlock_irqrestore(&dsolock, flags);
	}
}
