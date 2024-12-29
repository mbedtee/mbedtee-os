// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Process related ELF functions
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
#include <vma.h>
#include <kvma.h>
#include <kmalloc.h>
#include <uaccess.h>
#include <cacheops.h>
#include <page_scatter.h>
#include <process.h>
#include <elf_load.h>
#include <elf_proc.h>

#include "elf_priv.h"

/*
 * Structure for describing the Process's
 * private page mapping to store the dependent
 * DSO's LOADs (e.g. mapping libc.so LOADs)
 */
struct elf_loadmap {
	struct page **pages; /* own RW pages */
	Elf_Addr addr;

	int align;
	int nr_pages;

	/* map stat */
	bool kva_mapped;
	bool uva_mapped;
	/*
	 * RO-MAP only do the map for dependances' RO pages, no need to
	 * re-allocate pages while the RW-MAP still allocates the new pages
	 */
	bool is_rwmap;
};

/*
 * Structure for mapping the dependent DSO object
 */
struct elf_map {
	struct list_head node;

	/*
	 * based on which dependent DSO object
	 */
	struct elf_obj *obj;

	/*
	 * runtime address addend (virtual), possible values:
	 * NULL: for non-pie executable Apps - using the LOAD's vaddr
	 * ASLR: for pie executable Apps or Dynamic libs (DSO)
	 */
	void *l_addr;

	/*
	 * temporary kernel va, 2 purposes:
	 * 1. copy the RW LOAD to process's private pages
	 * 2. relocate the DSO with l_addr
	 *
	 * after finish these two steps, kva will be unmapped/freed.
	 */
	void *kva;

	/*
	 * mapping structure of each DSO LOAD
	 */
	struct elf_loadmap loadm[];
};

static Elf_Word elf_hash(const char *name)
{
	Elf_Word h = 0, g = 0;

	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		h ^= g >> 24;
	}
	return h & 0x0fffffff;
}

/*
 * Get the application local symbol load address
 * according to the specified local symbol name.
 *
 * (For parsing application local symbols only)
 */
static void *elf_sym(struct elf_obj *obj, const char *name)
{
	Elf_Sym *sym = NULL;

	if (obj->symtab) {
		for (sym = obj->symtab; sym < obj->symtab + obj->symnum; sym++) {
			if ((ELF_ST_TYPE(sym->st_info) != STT_FUNC) ||
				(sym->st_shndx == SHN_UNDEF))
				continue;

			if (strncmp(obj->strtab + sym->st_name, name, 255) == 0)
				return obj->l_addr + sym->st_value;
		}
		LMSG("%s not found in %s\n", name, obj->name);
	}

	return NULL;
}

/*
 * Get the dynamic symbol run address according to the
 * specified dynamic symbol name.
 */
void *elf_dynsym(struct elf_obj *obj, const char *name)
{
	Elf_Word symidx = 0;
	Elf_Word nbucket = 0;
	Elf_Word *bucket = NULL;
	Elf_Word *chain = NULL;
	Elf_Sym *ref_sym = NULL;
	struct elf_obj *ref_obj = NULL;
	Elf_Sym *ref_symtab = NULL;
	struct elf_map *m = NULL;
	Elf_Word hash = elf_hash(name);

	list_for_each_entry(m, &obj->maps, node) {
		ref_obj = m->obj;
		nbucket = *ref_obj->hash;
		bucket = ref_obj->hash + 2;
		chain = &bucket[nbucket];
		ref_symtab = ref_obj->dynsym;

		symidx = bucket[hash % nbucket];

		do {
			ref_sym = &ref_symtab[symidx];

			if (ref_sym->st_shndx == SHN_UNDEF)
				continue;

			if (strcmp(ref_obj->dynstr + ref_sym->st_name, name) == 0)
				return m->l_addr + ref_sym->st_value;
		} while ((symidx = chain[symidx]) != 0);
	}

	EMSG("%s not found\n", name);
	return NULL;
}

/*
 * process the external dynamic symbol entries (e.g. symbols from
 * the DSO - e.g. libc.so, user space wrapper function entries)
 */
static void elf_dynamic_symbols(struct process *proc)
{
	struct elf_obj *obj = proc->obj;
	struct process_wrapper *wrapper = &proc->pself->wrapper;

	wrapper->proc_entry = elf_dynsym(obj, "process_entry");
	wrapper->pthread_entry = elf_dynsym(obj, "pthread_entry");
	wrapper->signal_entry = elf_dynsym(obj, "signal_entry");
	wrapper->backtrace = elf_dynsym(obj, "backtrace");
	wrapper->open = elf_dynsym(obj, "pthread_session_open");
	wrapper->invoke = elf_dynsym(obj, "pthread_session_invoke");
	wrapper->close = elf_dynsym(obj, "pthread_session_close");
}

/*
 * process the App local symbol entries (e.g.
 * App GlobalPlatform function entries)
 */
static int elf_local_symbols(struct process *proc)
{
	struct elf_obj *obj = proc->obj;
	struct process_gp *gp = &proc->pself->gp;
	void *entry = NULL;

	/*
	 * found the main()
	 */
	entry = elf_sym(obj, "main");
	if (entry != NULL) {
		proc->main_func = entry;
		return 0;
	}

	gp->create = elf_sym(obj, "TA_CreateEntryPoint");
	gp->destroy = elf_sym(obj, "TA_DestroyEntryPoint");
	gp->open = elf_sym(obj, "TA_OpenSessionEntryPoint");
	gp->close = elf_sym(obj, "TA_CloseSessionEntryPoint");
	gp->invoke = elf_sym(obj, "TA_InvokeCommandEntryPoint");

	return 0;
}

/*
 * Parse the local/dynamic symbol entries
 */
static int elf_proc_entry(struct process *proc)
{
	elf_dynamic_symbols(proc);

	return elf_local_symbols(proc);
}

static int elf_proc_relocate(struct elf_obj *obj)
{
	int ret = -1;
	struct elf_map *m = NULL;

	list_for_each_entry(m, &obj->maps, node) {
		ret = elf_relocate(m->obj, m->l_addr, m->kva);
		if (ret != 0)
			return ret;
	}

	return elf_relocate(obj, obj->l_addr, obj->kva);
}

#ifdef CONFIG_USER_BACKTRACE
/*
 * aarch64, riscv and mips use the .eh_frame for unwinding
 * arm uses the .ARM.exidx and .ARM.extab for unwinding
 */
static void *elf_get_unwind_info(struct elf_obj *obj,
	int *sh_size)
{
	const char *unwindtab = NULL;
	Elf_Ehdr *hdr = obj->hdr;
	Elf_Shdr *shdr = obj->shdr;
	Elf_Shdr *sh = NULL;

	unwindtab = (hdr->e_machine != EM_ARM) ? ".eh_frame" : ".ARM.exidx";

	for (sh = shdr; sh < shdr + hdr->e_shnum; sh++) {
		if (strncmp(obj->shstr + sh->sh_name, unwindtab, 12) == 0) {
			*sh_size = sh->sh_size;
			return (void *)sh->sh_addr;
		}
	}

	return 0;
}

static void elf_proc_unwind_info(struct process *proc,
	void *tab, int tabsz, void *l_addr, int l_size)
{
	int i = 0, nrtabs = 0;
	struct __process *pself = proc->pself;

	tab += (unsigned long)l_addr;

	nrtabs = min(pself->unwind.nrtabs, MAX_UNWIND_TABLES);
	for (i = 0; i < nrtabs; i++) {
		if (tab == pself->unwind.tabs[i])
			break;
	}

	if (i != nrtabs)
		return;

	if (nrtabs == MAX_UNWIND_TABLES)
		return;
	pself->unwind.tabs[nrtabs] = tab;
	pself->unwind.tabsize[nrtabs] = tabsz;

	pself->unwind.l_addr[nrtabs] = l_addr;
	pself->unwind.l_size[nrtabs] = l_size;

	pself->unwind.nrtabs = nrtabs + 1;
}

static char *__elf_funcname(struct elf_obj *obj,
	unsigned long runaddr, unsigned long *offset, void *l_addr)
{

	Elf_Sym *symtab = obj->symtab;
	char *strtab = obj->strtab;
	Elf_Sym *sym = NULL;
	unsigned long symaddr = 0;
	unsigned int i = 0;

	/* .symtab or .symstr not present */
	if (!symtab || !strtab)
		return NULL;

	symaddr = runaddr - (unsigned long)l_addr;

	/* not in this ELF */
	if (((long)symaddr < 0) || (symaddr - obj->vbase > obj->size))
		return NULL;

	for (i = 0; i < obj->symnum; i++) {
		sym = &symtab[i];
		if ((ELF_ST_TYPE(sym->st_info) == STT_FUNC) &&
			(sym->st_shndx != SHN_UNDEF)) {
			if ((symaddr >= sym->st_value) &&
				(symaddr < sym->st_value + sym->st_size)) {
				if (offset)
					*offset = symaddr - sym->st_value;
				return strtab + sym->st_name;
			}
		}
	}

	return NULL;
}
#endif

/*
 * for backtrace purpose
 * Get the .eh_frame or .exidx section addr.
 *
 * aarch64, riscv and mips use the .eh_frame for unwinding
 * arm uses the .ARM.exidx and .ARM.extab for unwinding
 */
static void elf_proc_unwinding(struct process *proc)
{
#ifdef CONFIG_USER_BACKTRACE
	struct elf_obj *dso = NULL;
	struct elf_obj *obj = proc->obj;
	struct elf_map *m = NULL;
	void *tab = NULL;
	int sh_size = 0;

	list_for_each_entry(m, &obj->maps, node) {
		dso = m->obj;

		tab = elf_get_unwind_info(dso, &sh_size);

		if (tab) {
			elf_proc_unwind_info(proc, tab, sh_size, m->l_addr, dso->size);

			LMSG("unwinding-tabs[%d]@%s %p\n",
				proc->pself->unwind.nrtabs, dso->name, tab);
		}

		tab = NULL;
	}

	tab = elf_get_unwind_info(obj, &sh_size);
	if (tab) {
		elf_proc_unwind_info(proc, tab, sh_size, obj->l_addr, obj->size);

		LMSG("unwinding-tabs[%d]@%s %p\n",
			proc->pself->unwind.nrtabs, obj->name, tab);
	}
#endif
}

/*
 * for backtrace purpose
 * Get the function name based on the function run addr.
 *
 * To use this function, the .symtab and .strtab must be present in ELF.
 * Note that: "strip -s or strip --strip-unneeded" removes these
 * two sections,  thus Programmer shall use "strip --strip-debug"
 * to keep them in ELF.
 */
static char *elf_funcname(struct elf_obj *obj,
	unsigned long runaddr, unsigned long *offset)
{
#ifdef CONFIG_USER_BACKTRACE
	char *funcname = NULL;
	struct elf_obj *dso = NULL;
	struct elf_map *m = NULL;

	/* search it in dependent DSOs */
	list_for_each_entry(m, &obj->maps, node) {
		dso = m->obj;
		funcname = __elf_funcname(dso, runaddr, offset, m->l_addr);
		if (funcname)
			return funcname;
	}

	/* search it in current executable */
	return __elf_funcname(obj, runaddr, offset, obj->l_addr);

#endif
	return NULL;
}

/*
 * unloading for a process ELF
 */
void elf_unload_proc(struct process *proc)
{
	int i = 0;
	struct elf_obj *obj = NULL, *dso = NULL;
	struct elf_ld *load = NULL;
	struct elf_loadmap *lm = NULL;
	struct elf_map *m = NULL, *n = NULL;

	obj = proc->obj;
	if (obj == NULL)
		return;

	proc->obj = NULL;

	/*
	 * unmap the dependances (DSO)
	 */
	list_for_each_entry_safe(m, n, &obj->maps, node) {
		dso = m->obj;
		for (i = 0; i < dso->nrloads; i++) {
			lm = &m->loadm[i];

			if (lm->uva_mapped) {
				pages_sc_unmap(lm->pages, proc->pt,
					m->l_addr + rounddown(lm->addr, lm->align),
					lm->nr_pages);
			}

			if (lm->is_rwmap) {
				if (lm->kva_mapped)
					pages_sc_unmap(lm->pages, kpt(), m->kva +
						rounddown(lm->addr, lm->align), lm->nr_pages);
				pages_sc_free(lm->pages, lm->nr_pages);
			}
		}

		if (m->l_addr)
			vma_free(proc->vm, m->l_addr + dso->vbase);

		if (m->kva)
			kvma_free(m->kva + dso->vbase);

		list_del(&m->node);
		kfree(m);
	}

	/*
	 * unmap current executable object file
	 */
	list_for_each_entry(load, &obj->loads, node) {
		if (load->uva_mapped)
			pages_sc_unmap(load->pages, proc->pt, obj->l_addr +
				rounddown(load->addr, load->align), load->nr_pages);
	}

	if (obj->l_addr)
		vma_free(proc->vm, obj->l_addr + obj->vbase);

	elf_unload(obj);
}

static int elf_map_dependances(struct process *proc, struct elf_obj *obj)
{
	struct elf_needed *needed = NULL;
	struct elf_ld *load = NULL;
	struct elf_map *m = NULL;
	struct elf_loadmap *lm = NULL;
	struct elf_obj *dst = NULL;
	Elf_Addr offset = 0;
	int ret = -ENOMEM;

	/*
	 * Map the dependances (DSO):
	 * 1. map RO/EXEC segments
	 * 2. alloc/map RW segments
	 */
	list_for_each_entry(needed, &obj->needs, node) {
		dst = needed->obj;

		ret = elf_map_dependances(proc, dst);
		if (ret != 0)
			goto out;

		list_for_each_entry(m, &proc->obj->maps, node) {
			if (dst == m->obj)
				goto out;
		}

		ret = -ENOMEM;
		m = kzalloc(sizeof(struct elf_map) +
				(sizeof(struct elf_loadmap) * dst->nrloads));
		if (m == NULL)
			goto out;

		m->obj = dst;

		list_add_tail(&m->node, &proc->obj->maps);

		m->l_addr = vma_alloc(proc->vm, dst->size);
		if (!m->l_addr)
			goto out;

		m->l_addr -= dst->vbase;

		m->kva = kvma_alloc(dst->size);
		if (!m->kva)
			goto out;

		m->kva -= dst->vbase;

		lm = m->loadm;

		list_for_each_entry(load, &dst->loads, node) {

			ret = -ENOMEM;

			LMSG("nr_pages %ld -> %p + %lx = %p\n", (long)load->nr_pages,
				 m->l_addr, (long)load->addr, m->l_addr + load->addr);

			offset = rounddown(load->addr, load->align);
			lm->is_rwmap = ((load->flags & PG_RW) == PG_RW);
			lm->addr = load->addr;
			lm->align = load->align;
			lm->nr_pages = load->nr_pages;
			if (lm->is_rwmap) {
				lm->pages = pages_sc_alloc(load->nr_pages);
				if (lm->pages == NULL)
					goto out;

				ret = pages_sc_map(lm->pages, kpt(), m->kva + offset,
							load->nr_pages, PG_RW);
				if (ret != 0)
					goto out;

				lm->kva_mapped = true;

				ret = pages_sc_map(lm->pages, proc->pt, m->l_addr + offset,
							load->nr_pages, load->flags);
				if (ret != 0)
					goto out;

				lm->uva_mapped = true;

				memcpy(m->kva + offset, dst->kva + offset,
					load->nr_pages << PAGE_SHIFT);
			} else {
				ret = pages_sc_map(load->pages, proc->pt, m->l_addr + offset,
							load->nr_pages, load->flags);
				if (ret != 0)
					goto out;
				lm->pages = load->pages;
				lm->uva_mapped = true;
			}

			lm++;
		}
	}

	return 0;

out:
	return ret;
}

static int elf_map_application(struct process *proc, struct elf_obj *obj)
{
	struct elf_ld *load = NULL;
	void *l_addr = NULL;
	int ret = -ENOMEM;

	if (obj->is_pie) {
		l_addr = vma_alloc(proc->vm, obj->size);
		if (!l_addr)
			goto out;
		l_addr -= obj->vbase;
	}

	obj->l_addr = l_addr;

	/*
	 * Map current executable object file:
	 * 1. map RO/EXEC segments
	 * 2. map RW segments
	 */
	list_for_each_entry(load, &obj->loads, node) {
		ret = pages_sc_map(load->pages, proc->pt, l_addr +
				rounddown(load->addr, load->align),
				load->nr_pages, load->flags);

		LMSG("nr_pages %ld -> %p + %lx = %p vbase=%p\n", (long)load->nr_pages,
			 l_addr, (long)load->addr, l_addr + load->addr, (void *)obj->vbase);

		if (ret != 0)
			goto out;

		load->uva_mapped = true;
	}

	return 0;

out:
	return ret;
}

/*
 * Free the unneeded resources of the LOAD segments
 * (part of the resource are not needed,
 * such as the kernel VA mapping of the applications)
 */
static void elf_free_unused(struct elf_obj *obj)
{
	int i = 0;
	struct elf_map *m = NULL;
	struct elf_loadmap *lm = NULL;
	struct elf_ld *load = NULL;

	if (obj->is_app) {
		list_for_each_entry(load, &obj->loads, node) {
			if (load->kva_mapped) {
				load->kva_mapped = false;
				pages_sc_unmap(load->pages, kpt(), obj->kva +
					rounddown(load->addr, load->align), load->nr_pages);
			}
		}
		kvma_free(obj->kva + obj->vbase);
		obj->kva = NULL;
	}

	list_for_each_entry(m, &obj->maps, node) {
		for (i = 0; i < m->obj->nrloads; i++) {
			lm = &m->loadm[i];
			if (lm->kva_mapped) {
				lm->kva_mapped = false;
				pages_sc_unmap(lm->pages, kpt(), m->kva +
					rounddown(lm->addr, lm->align), lm->nr_pages);
			}
		}
		kvma_free(m->kva + m->obj->vbase);
		m->kva = NULL;
	}
}

/*
 * loading for a process ELF
 */
int elf_load_proc(struct process *proc)
{
	struct elf_obj *obj = NULL;
	int ret = -ENOMEM;

	obj = elf_load(proc->c->path);
	if (!obj)
		return -ENOMEM;

	proc->obj = obj;

	LMSG("%s allocated\n", proc->c->path);

	/*
	 * Map the dependances (DSO):
	 * 1. map RO/EXEC segments
	 * 2. alloc/map RW segments
	 */
	ret = elf_map_dependances(proc, obj);
	if (ret != 0)
		goto out;

	LMSG("%s dependances mapped\n", proc->c->path);

	/*
	 * Map current executable application:
	 * 1. map RO/EXEC segments
	 * 2. map RW segments
	 */
	ret = elf_map_application(proc, obj);
	if (ret != 0)
		goto out;

	LMSG("%s app mapped\n", proc->c->path);

	ret = elf_proc_relocate(obj);
	if (ret != 0)
		goto out;

	ret = elf_proc_entry(proc);
	if (ret != 0)
		goto out;

	elf_proc_unwinding(proc);

	elf_free_unused(obj);

	flush_icache_all();
	return 0;

out:
	elf_unload_proc(proc);
	return ret;
}

const char *elf_proc_funcname(struct process *proc,
	unsigned long runaddr, unsigned long *offset)
{
	if (!user_addr(runaddr))
		return ksymname_of(runaddr, offset);

	if (proc == NULL)
		return NULL;

	return elf_funcname(proc->obj, runaddr, offset);
}
