// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * FAT FS (only for RAM based)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <timer.h>
#include <ktime.h>
#include <sys/stat.h>
#include <errno.h>
#include <kmalloc.h>

#include <mutex.h>
#include <fs.h>
#include <fatfs.h>

#include "fatfs_priv.h"

#define lock_fatfs(fs) mutex_lock(&((fs)->lock))
#define unlock_fatfs(fs) mutex_unlock(&((fs)->lock))

static const uint8_t lfnoff[LDIR_NAME_BYTES] = {
	1, 3, 5, 7, 9,              /* 0 ~ 4 */
	14, 16, 18, 20, 22, 24,     /* 5 ~ 10 */
	28, 30                      /* 11 ~ 12 */
};

static inline uint8_t sfnsum(char *s)
{
	uint8_t sum = 0, len = 11;

	for (; len != 0; len--)
		sum = (sum << 7) + (sum >> 1) + *s++;

	return sum;
}

static inline struct fatfs *file2fatfs(struct file *f)
{
	return (struct fatfs *)f->fs->priv;
}

static inline int clst_get(struct fatfs *fs,
	struct direnty *dir)
{
	if (fs->type == FAT32)
		return (((int)dir->starthi << 16) | dir->startlo);
	else
		return dir->startlo;
}

static inline void clst_set(struct fatfs *fs,
	struct direnty *dir, int clst)
{
	dir->startlo = (clst) & 0xffff;
	if (fs->type == FAT32)
		dir->starthi = (clst >> 16) & 0xffff;
}

static inline int clst2sect(struct fatfs *fs, int clst)
{
	if (clst < 2 || clst >= fs->nr_fatent)
		return -ENOENT;

	return fs->database + fs->csize * (clst - 2);
}

static inline char *sect2mem(struct fatfs *fs, int sect)
{
	if (sect < 0)
		return NULL;

	return fs->membase + fs->ssize * sect;
}

static inline char *clst2mem(struct fatfs *fs, int clst)
{
	return sect2mem(fs, clst2sect(fs, clst));
}

static inline struct ldirenty *sect2dir(struct fatfs *fs, int sect)
{
	return (struct ldirenty *)sect2mem(fs, sect);
}

static int fatent_get(struct fatfs *fs, int clst)
{
	int val = -ENOENT;
	char *mem = sect2mem(fs, fs->fatbase);

	if (invalid_clst(clst))
		return val;

	switch (fs->type) {
	case FAT12:
		val = load16h(mem + clst + clst / 2);
		val = (clst & 1) ? (val >> 4) : (val & 0xFFF);
		break;

	case FAT16:
		val = load16h(mem + clst * 2);
		break;

	case FAT32:
		val = load32h(mem + clst * 4) & 0x0FFFFFFF;
		break;

	default:
		break;
	}

	return val;
}

static void fatent_set(struct fatfs *fs, int clst, int nclst)
{
	int off = 0, val = 0, tmp = 0;
	char *mem = sect2mem(fs, fs->fatbase);

	if (invalid_clst(clst))
		return;

	switch (fs->type) {
	case FAT12:
		off = clst + clst / 2;
		val = (clst & 1) ? ((load8h(mem + off) & 0x0F)
				| ((uint8_t)nclst << 4)) : (uint8_t)nclst;
		tmp = (clst & 1) ? (nclst >> 4) : ((load8h(mem + off + 1) & 0xF0)
				| ((nclst >> 8) & 0x0F));
		val |= tmp << 8;
		store16h(val, mem + off);
		break;

	case FAT16:
		store16h(nclst, mem + clst * 2);
		break;

	case FAT32:
		nclst &= 0x0FFFFFFF;
		nclst |= load32h(mem + clst * 4) & 0xF0000000;
		store32h(nclst, mem + clst * 4);
		break;

	default:
		break;
	}
}

static int lfncmp(struct ldirenty *e, char *lfn)
{
	int i = 0, off = 0;
	uint16_t c = 0, lc = 1;

	if (e->start != 0)
		return -ENOENT;

	off = ((e->ord & LFN_ENTRY_MASK) - 1) * LDIR_NAME_BYTES;

	for (i = 0; i < LDIR_NAME_BYTES && off < FAT_MAX_LFN + 1; i++) {
		c = load16h((char *)e + lfnoff[i]);
		if (lc != 0) {
			if (toupper(c & 0xff) != toupper(lfn[off++]))
				return -ENOENT;
			lc = c;
		} else {
			if (c != 0xFFFF)
				return -ENOENT;
		}
	}

	/* not finished?? */
	if ((e->ord & LAST_LONG_ENTRY) && lc && lfn[off])
		return -ENOENT;

	return 0;
}

static int lfnget(struct ldirenty *e, char *lfn)
{
	int i = 0, off = 0, cnt = 0;
	uint16_t c = 0, lc = 1;

	off = ((e->ord & LFN_ENTRY_MASK) - 1) * LDIR_NAME_BYTES;

	for (i = 0; i < LDIR_NAME_BYTES && off < FAT_MAX_LFN; i++) {
		c = load16h((char *)e + lfnoff[i]);
		if (lc != 0) {
			lfn[off++] = c;
			lc = c;
			cnt++;
		} else {
			if (c != 0xFFFF)
				return -ENOENT;
		}
	}

	if ((e->ord & LAST_LONG_ENTRY) && lc) {
		lfn[off] = 0;
		cnt++;
	}

	return cnt;
}

static void lfn2sfn(struct d_info *di)
{
	int dot_i = di->fn_size, sfn_i = 0, lfn_i = 0;
	uint8_t c = 0, multicase = false, lcase = false;

	if (dot_i == 0)
		return;

	memset(di->sfn, ' ', FAT_MAX_SFN);

	while (--dot_i > 0 && di->lfn[dot_i] != '.')
		;

	for (lfn_i = 0; lfn_i < di->fn_size && sfn_i < FAT_SFN_NAME; lfn_i++) {
		c = di->lfn[lfn_i];
		if (c == 0)
			break;

		if (dot_i && (lfn_i == dot_i))
			break;

		if (c == ' ' || c == '.') {
			di->fn_flag |= FN_IS_LFN;
			continue;
		}

		di->sfn[sfn_i++] = toupper(c);
	}

	if (dot_i == 0 && (di->fn_size > FAT_SFN_NAME))
		di->fn_flag |= FN_IS_LFN;

	/* case sensisive for SFN ?? */
	if ((di->fn_flag & FN_IS_LFN) == 0) {
		lfn_i = 0;
		while ((c = di->lfn[lfn_i]) != 0 && !isalpha(c))
			lfn_i++;
		c = di->lfn[lfn_i++];

		if (c && (c != '.')) {
			lcase = islower(c);
			while (((c = di->lfn[lfn_i]) != 0) && (c != '.')) {
				if (isalpha(c) && (islower(c) != lcase))
					multicase = true;
				lfn_i++;
			}
			di->fn_case = lcase ? FN_LOWER_NAME : 0;
		}
	}

	if (dot_i > 0) {
		sfn_i = FAT_SFN_NAME;
		lfn_i = dot_i + 1;
		while (sfn_i < FAT_MAX_SFN) {
			c = di->lfn[lfn_i++];
			if (c == 0)
				break;
			di->sfn[sfn_i++] = toupper(c);
		}

		if (dot_i > FAT_SFN_NAME ||
			di->fn_size > dot_i + FAT_SFN_EXT + 1)
			di->fn_flag |= FN_IS_LFN;

		/* case sensisive for SFN ext ?? */
		if ((di->fn_flag & FN_IS_LFN) == 0) {
			while ((c = di->lfn[++dot_i]) != 0 && !isalpha(c))
				dot_i++;
			c = di->lfn[dot_i];
			if (c) {
				lcase = islower(c);
				while ((c = di->lfn[++dot_i]) != 0) {
					if (isalpha(c) && (islower(c) != lcase))
						multicase = true;
				}
				di->fn_case |= lcase ? FN_LOWER_EXT : 0;
			}
		}
	}

	if (multicase)
		di->fn_flag |= FN_IS_LFN;
}

static int sfnget(struct direnty *e, char *sfn)
{
	int lcase = e->ntres, i = 0, j = 0;
	char name[FAT_SFN_NAME];
	char ext[FAT_SFN_EXT];

	memcpy(name, e->name, FAT_SFN_NAME);
	memcpy(ext, e->ext, FAT_SFN_EXT);

	for (i = 0; i < FAT_SFN_NAME && name[i] != ' '; i++)
		sfn[i] = lcase & FN_LOWER_NAME ? tolower(name[i]) : name[i];

	if (ext[0] != ' ') {
		sfn[i++] = '.';
		for (j = 0; j < FAT_SFN_EXT && ext[j] != ' '; j++)
			sfn[i++] = lcase & FN_LOWER_EXT ? tolower(ext[j]) : ext[j];
	}

	sfn[i] = 0;

	return strlen(sfn) + 1;
}

static void sync_freeclst(struct fatfs *fs, int freed)
{
	fs->free_clst += freed;

	if (fs->fsi_sec) {
		store32h(fs->last_clst, fs->fsi_sec + FSI_LAST_CLST);
		store32h(fs->free_clst, fs->fsi_sec + FSI_FREE_CLST);
	}
}

static inline int nr_freeclst(struct fatfs *fs)
{
	int nclst = 0, tclst = 0, fclst = 0;

	for (nclst = 2; !invalid_clst(nclst); nclst++) {
		tclst = fatent_get(fs, nclst);
		if (tclst == 0)
			fclst++;
	}
	return fclst;
}

static int clst_enough(struct fatfs *fs, int request)
{
	if (request <= 0)
		return true;

	return request <= fs->free_clst;
}

static int clst_alloc(struct fatfs *fs, int clst)
{
	int sclst = 0, nclst = 0, tclst = 0;

	if (clst) {
		/* already have next valid clst ? */
		sclst = fatent_get(fs, clst);
		if (!invalid_clst(sclst))
			return sclst;
		sclst = clst;
	} else {
		sclst = fs->last_clst;
		if (invalid_clst(sclst))
			sclst = 1;
	}

	if (fs->free_clst == 0)
		return -ENOSPC;

	/* find a new one */
	for (nclst = sclst + 1; nclst != sclst; nclst++) {
		if (invalid_clst(nclst)) {
			if (sclst < 2)
				return -ENOSPC;
			nclst = 2;
		}

		tclst = fatent_get(fs, nclst);
		if (tclst == 0)
			break;
	}

	/* not found */
	if (tclst && (nclst == sclst))
		return -ENOSPC;

	fatent_set(fs, nclst, -1);
	if (clst)
		fatent_set(fs, clst, nclst);

	fs->last_clst = nclst;
	sync_freeclst(fs, -1);

	memset(clst2mem(fs, nclst), 0, fs->cbytes);
	return nclst;
}

static void clst_free(struct fatfs *fs, int clst, int parent)
{
	int nclst = 0, freed = 0;

	if (invalid_clst(clst))
		return;

	fatent_set(fs, parent, -1);

	fs->last_clst = clst - 1;

	do {
		nclst = fatent_get(fs, clst);

		FMSG("curr %d, next %d\n", clst, nclst);

		fatent_set(fs, clst, 0);
		freed++;
		memset(clst2mem(fs, clst), 0, fs->cbytes);
		clst = nclst;
	} while (!invalid_clst(clst));

	sync_freeclst(fs, freed);
}

static struct f_lock *list_cached_lock_clst(struct fatfs *fs,
	int clst)
{
	struct f_lock *l = NULL, *n = NULL;

	/* check the caching list */
	list_for_each_entry(n, &fs->llocks, node) {
		if (n->dir && (clst_get(fs, n->dir) == clst)) {
			l = n;
			break;
		}
	}

	return l;
}

static void fnclst_free(struct fatfs *fs,
	int sclst, int fnstart)
{
	struct ldirenty *ldir = NULL;
	int num = fs->cbytes / sizeof(struct ldirenty), n = 0;
	int prev = sclst, clst = 0, next = 0;
	off_t off = rounddown(fnstart, fs->cbytes);
	struct f_lock *l = NULL;

	if ((prev == 0) && (fs->type == FAT32))
		prev = fs->dirbase;

	if (!invalid_clst(prev)) {
		l = list_cached_lock_clst(fs, prev);
		if (l != NULL) {
			/*
			 * parent dir was opened,
			 * postpone the free to parent dir close()
			 */
			l->freefn = true;
			return;
		}
	}

	while (off > fs->cbytes) {
		prev = fatent_get(fs, prev);
		off -= fs->cbytes;
	}

	clst = fatent_get(fs, prev);
	if (invalid_clst(clst))
		return;

	while ((ldir = sect2dir(fs, clst2sect(fs, clst))) != NULL) {
		for (n = 0; n < num; n++) {
			if (ldir->ord && (ldir->ord != DIRENT_DEM))
				break;
			ldir++;
		}

		next = fatent_get(fs, clst);
		if (n == num) {
			memset(ldir - num, 0, fs->cbytes);
			fatent_set(fs, prev, next);
			fatent_set(fs, clst, 0);
			FMSG("prev %d, curr %d, next %d\n", prev, clst, next);
			sync_freeclst(fs, 1);
		} else {
			prev = clst;
		}

		clst = next;
	}
}

static struct f_lock *list_cached_lock(struct fatfs *fs,
	struct direnty *dir)
{
	struct f_lock *l = NULL, *n = NULL;

	if (dir == NULL)
		return NULL;

	/* check the caching list */
	list_for_each_entry(n, &fs->llocks, node) {
		if (n->dir == dir) {
			l = n;
			break;
		}
	}
	return l;
}

static int chk_cached_lock(struct fatfs *fs,
	struct direnty *dir)
{
	struct f_lock *l = list_cached_lock(fs, dir);

	/* check the caching list */
	if (l != NULL) {
		if (l->unlink)
			return -ENOENT;

		if (l->refc + 1 == LOCK_MAX_REFC)
			return -ENFILE;
	}

	return 0;
}

static struct f_lock *alloc_lock(struct fatfs *fs,
	struct direnty *dir)
{
	struct f_lock *l = NULL;

	l = list_cached_lock(fs, dir);
	if (l == NULL) {
		l = kzalloc(sizeof(struct f_lock));
		if (l != NULL) {
			INIT_LIST_HEAD(&l->files);
			INIT_LIST_HEAD(&l->node);
		}
	}

	return l;
}

static void get_lock(struct fatfs *fs, struct f_info *fi)
{
	struct f_lock *l = fi->lock;

	l->refc++;
	l->dir = fi->dir;
	list_add_tail(&fi->node, &l->files);

	if (list_empty(&l->node))
		list_add_tail(&l->node, &fs->llocks);
}

static void put_lock(struct fatfs *fs, struct f_info *fi)
{
	struct f_lock *l = fi->lock;

	list_del(&fi->node);

	if (--l->refc <= 0) {
		list_del(&l->node);

		if (l->unlink) { /* free clsts of file content */
			clst_free(fs, fi->sclst, 0);
			kfree(l->dir);
		}

		if (l->freefn) /* free clsts of dir's file name */
			fnclst_free(fs, fi->sclst, 0);

		kfree(l);
	}
}

static inline int calc_seekhole(size_t filesize,
	size_t cbytes, size_t off)
{
	size_t ext = 0, hole = 0;

	ext = roundup(filesize, cbytes);
	if (off > ext) {
		ext = roundup(off - ext, cbytes);
		hole = ext / cbytes;
	}
	return hole;
}

/*
 * free the superfluous seek holes
 */
static inline void free_seekhole(struct f_info *fi)
{
	int clst = 0;
	off_t off = 0;
	struct fatfs *fs = fi->fs;

	off = max((int)fi->dir->filesize, fi->offset);
	clst = off ? fi->sclst : 0;
	while (off > 0) {
		off -= fs->cbytes;
		clst = off > 0 ? fatent_get(fs, clst) : clst;
	}
	clst_free(fs, fatent_get(fs, clst), clst);
}

static struct ldirenty *dirent_next(struct d_info *di,
	int grow)
{
	int off = di->offset, clst = 0;
	struct ldirenty *ldir = di->ldir;
	struct fatfs *fs = di->fs;

	ldir++;

	off += sizeof(struct ldirenty);

	/* next sector ? */
	if (off % fs->ssize == 0) {
		di->sect++;

		/* FAT12/16 limits the number of root directory entries */
		if ((di->clst == 0) && invalid_rootdir(off))
			return NULL;

		ldir = sect2dir(fs, di->sect);

		/* next cluster ? */
		if (di->clst && ((off & (fs->cbytes - 1)) == 0)) {
			clst = fatent_get(fs, di->clst);
			if (invalid_clst(clst)) {
				if (grow == false)
					return NULL;
				clst = clst_alloc(fs, di->clst);
				if (invalid_clst(clst))
					return NULL;
			}
			di->clst = clst;
			di->sect = clst2sect(fs, clst);

			FMSG("fatent_get clst %d sect %d\n", di->clst, di->sect);
			ldir = sect2dir(fs, di->sect);
		}
	}

	di->offset = off;
	di->ldir = ldir;
	di->dir = (struct direnty *)ldir;
	return ldir;
}

/*
 * restart from the start claster
 */
static struct ldirenty *dirent_renew(struct d_info *di, off_t offset)
{
	char *mem = NULL;
	struct ldirenty *ldir = NULL;
	struct fatfs *fs = di->fs;
	off_t clst = 0, sect = 0, off = offset;

	if (offset < 0)
		return NULL;

	if (di->sclst == 0) {
		if (fs->type != FAT32) {
			clst = 0;
			sect = fs->dirbase;
		} else {
			clst = fs->dirbase;
			sect = clst2sect(fs, clst);
		}
	} else {
		clst = di->sclst;
		sect = clst2sect(fs, clst);
	}

	/* FAT12/16 limits the number of root directory entries */
	if ((clst == 0) && invalid_rootdir(off))
		return NULL;

	if (off && clst) {
		while (off >= fs->cbytes) {
			clst = fatent_get(fs, clst);
			if (invalid_clst(clst))
				return NULL;
			off -= fs->cbytes;
		}
		sect = clst2sect(fs, clst);
	}

	sect += off / fs->ssize;

	mem = sect2mem(fs, sect);
	if (mem == NULL)
		return NULL;

	mem += off % fs->ssize;
	ldir = (struct ldirenty *)mem;

	FMSG("clst %ld off 0x%lx -- sect %ld @ 0x%x\n", clst, offset,
		sect, (int)((char *)ldir - fs->membase));

	di->clst = clst;
	di->sect = sect;
	di->offset = offset;
	di->ldir = ldir;
	di->dir = (struct direnty *)ldir;

	return ldir;
}

static int follow_dir(struct d_info *di)
{
	uint8_t ord = -1, sum = -1;
	uint8_t attr = 0, c = 0;
	struct ldirenty *ldir = NULL;

	FMSG("finding lfn %s sfn %s fnflag 0x%x @ sclst %d off 0x%x\n",
		di->lfn, di->sfn, di->fn_flag, di->sclst, di->offset);

	/* is the root directory */
	if (di->fn_size == 0) {
		if (di->sclst || di->offset)
			return -ENOENT;
		di->dir = &di->fs->root;
		return 0;
	}

	ldir = dirent_renew(di, 0);
	if (ldir == NULL)
		return -ENOENT;

	do {
		/* end of the dir table */
		c = ldir->ord;
		if (c == 0)
			return -ENOENT;

		attr = ldir->attr & ATTR_MASK;
		if (c != DIRENT_DEM) {
			if (attr == ATTR_LFN) {
				/* LFN entry re-started with 0x40 flag */
				if (di->fn_flag & FN_IS_LFN) {
					if (c & LAST_LONG_ENTRY) {
						di->fn_start = di->offset;
						sum = ldir->checksum;
						ord = c & LFN_ENTRY_MASK;
						c = ord;
					}

					if ((c == ord) && (sum == ldir->checksum)
						 && (lfncmp(ldir, di->lfn) == 0))
						ord -= 1;
					else
						ord = -1;
				}
			} else {
				if ((ord == 0) && (sum == sfnsum(di->dir->name))) {
					FMSG("LFN matched sclst = %d off=0x%x\n",
						di->sclst, di->offset);
					return 0;
				} else if (!(di->fn_flag & FN_IS_LFN) && (ord == 255) &&
					!strncmp(di->dir->name, di->sfn, FAT_MAX_SFN)) {
					FMSG("SFN matched sclst = %d off=0x%x\n",
						di->sclst, di->offset);
					di->fn_start = di->offset;
					return 0;
				}

				ord = -1;
			}
		} else {
			ord = -1;
		}
	} while ((ldir = dirent_next(di, false)) != NULL);

	return -ENOENT;
}

static int follow_path_exclusion(struct d_info *di,
	const char *p, struct direnty *exclusion)
{
	int len = 0, ret = -ENOENT;

	while (*p == '/')
		p++;

	for (;;) {
		if (*p && *p != '/') {
			di->lfn[len++] = *p++;
			if ((len == FAT_MAX_LFN) &&
				(*p != '/') && (*p)) {
				ret = -ENAMETOOLONG;
				break;
			}
		} else {
			di->lfn[len] = 0;
			di->fn_size = len;
			di->fn_flag = 0;
			di->fn_case = 0;
			di->directory = ((*p && (*p++ == '/')) || (len == 0))
							? DIRENT_DIR : DIRENT_ARC;
			lfn2sfn(di);
			ret = follow_dir(di);
			if (ret != 0) {
				if (*p != '\0')
					di->abort = true;
				FMSG("%s not exist\n\n", di->lfn);
				break;
			} else if (di->dir == exclusion) {
				/*
				 * usually used on the judgement:
				 * 'rename to a subdirectory of itself'
				 */
				ret = -EINVAL;
				break;
			}

			while (*p == '/')
				p++;

			if (*p == '\0')
				break;

			di->sclst = clst_get(di->fs, di->dir);
			len = 0;
		}
	}

	return ret;
}

static inline int follow_path(struct d_info *di, const char *p)
{
	return follow_path_exclusion(di, p, NULL);
}

static int sfn_addnum(struct d_info *di)
{
	int sfn_i = 0, seq_i = 0, i = 0, num = 0, ret = -1;
	uint8_t c = 0, seq_c[FAT_SFN_NAME];

	if ((di->fn_flag & FN_IS_LFN) == 0)
		return 0;

	/*
	 * format short name, max to ~999
	 */
	di->fn_flag &= ~FN_IS_LFN; /* temporary do not check LFN */
	for (i = 1; i < 1000; i++) {
		num = i;
		sfn_i = 0;
		seq_i = FAT_SFN_NAME - 1;
		do {
			c = (num % 10) + '0';
			seq_c[seq_i--] = c;
			num /= 10;
		} while (num);
		seq_c[seq_i] = '~';

		while ((sfn_i < seq_i) && (di->sfn[sfn_i] != ' '))
			sfn_i++;

		while (sfn_i < FAT_SFN_NAME)
			di->sfn[sfn_i++] = (seq_i < FAT_SFN_NAME) ? seq_c[seq_i++] : ' ';

		ret = follow_dir(di);
		if (ret != 0)
			break;
	}
	di->fn_flag |= FN_IS_LFN; /* recover to check LFN */

	/*
	 * too many short names collide with each other
	 */
	if (i == 1000)
		return -ENOSPC;

	return 0;
}

static void lfnfill(struct ldirenty *ldir, char *lfn,
	uint8_t ord, uint8_t sum)
{
	uint16_t c = 0, lfn_i = 0, n = 0;

	ldir->attr = ATTR_LFN;
	ldir->checksum = sum;
	ldir->reserved = 0;
	ldir->start = 0;

	lfn_i = (ord - 1) * 13;

	do {
		if (c != 0xFFFF)
			c = lfn[lfn_i++];

		store16h(c, (uint8_t *)ldir + lfnoff[n]);

		if (c == 0)
			c = 0xFFFF;
	} while (++n < 13);

	if (c == 0xFFFF || lfn[lfn_i] == 0)
		ord |= LAST_LONG_ENTRY;

	ldir->ord = ord;
}

static int dirent_alloc(struct d_info *di)
{
	struct ldirenty *ldir = NULL;
	int num = (di->fn_size + 12) / 13 + 1, n = 0;

	if ((di->fn_flag & FN_IS_LFN) == 0)
		num = 1;

	ldir = dirent_renew(di, 0);
	if (ldir != NULL) {
		do {
			n += ((ldir->ord == 0) || (ldir->ord == DIRENT_DEM)) ? 1 : -n;
		} while ((n != num) && ((ldir = dirent_next(di, true)) != NULL));
	}

	return (n == num) ? 0 : -ENOSPC;
}

static void dirent_remove(struct d_info *di)
{
	off_t start = di->fn_start;
	off_t end = di->offset;
	struct ldirenty *ldir = NULL;

	FMSG("sclst %d start 0x%lx end 0x%lx\n",
		di->sclst, start, end + sizeof(*ldir));

	ldir = dirent_renew(di, start);
	if (ldir != NULL) {
		do {
			memset(ldir, 0, sizeof(struct ldirenty));
			ldir->ord = DIRENT_DEM;
			ldir = dirent_next(di, false);
			start += sizeof(struct ldirenty);
		} while ((start <= end) && ldir);
	}

	fnclst_free(di->fs, di->sclst, di->fn_start);
}

static void fatfs_update_time(uint16_t *d,
	uint16_t *t)
{
	time_t tsec = 0;
	struct tm tm, *v = &tm;

	get_systime(&tsec, NULL);

	time2date(tsec, &tm);

	if (d)
		*d = (v->tm_year + 1900 - 1980) << 9 | ++v->tm_mon << 5 | v->tm_mday;
	if (t)
		*t = v->tm_hour << 11 | v->tm_min << 5 | (v->tm_sec / 2);
}

static void dirent_fill(struct d_info *di)
{
	struct direnty *dir = NULL;
	struct ldirenty *ldir = NULL;
	uint8_t sum = 0;
	int num = (di->fn_size + 12) / 13 + 1;

	if ((di->fn_flag & FN_IS_LFN) == 0)
		num = 1;

	ldir = dirent_renew(di, di->offset - (num - 1)
		* sizeof(struct ldirenty));

	sum = sfnsum(di->sfn);

	while (ldir && --num) {
		lfnfill(ldir, di->lfn, num, sum);
		ldir = dirent_next(di, false);
	}

	if (ldir && (num == 0)) {
		dir = (struct direnty *)ldir;
		memset(dir, 0, sizeof(struct direnty));
		memcpy(dir->name, di->sfn, sizeof(dir->name));
		memcpy(dir->ext, &di->sfn[sizeof(dir->name)], sizeof(dir->ext));
		fatfs_update_time(&dir->cdate, &dir->ctime);
		dir->time = dir->ctime;
		dir->date = dir->cdate;
		dir->adate = dir->cdate;
		dir->ntres = di->fn_case;
		dir->attr = di->directory ? ATTR_DIR : ATTR_ARC;
		if ((di->mode & 0200) == 0)
			dir->attr |= ATTR_RO;
	}
}

static void dir_register(struct d_info *di, int clst)
{
	struct fatfs *fs = di->fs;
	struct direnty *dir = NULL;

	dir = (struct direnty *)clst2mem(fs, clst);
	if (dir == NULL)
		return;

	memset(dir, 0, sizeof(struct direnty));
	memset(dir->name, ' ', FAT_MAX_SFN);
	dir->name[0] = '.';
	dir->attr = ATTR_DIR;
	if ((di->mode & 0200) == 0)
		dir->attr |= ATTR_RO;
	fatfs_update_time(&dir->cdate, &dir->ctime);
	dir->date = dir->cdate;
	dir->time = dir->ctime;
	dir->adate = dir->cdate;
	clst_set(fs, dir, clst);

	dir++;
	memcpy(dir, dir - 1, sizeof(struct direnty));
	dir->name[1] = '.';
	clst_set(fs, dir, di->sclst);

	/* link it to parent dir */
	clst_set(fs, di->dir, clst);
}

static int dirent_register(struct d_info *di)
{
	int clst = 0;
	struct fatfs *fs = di->fs;
	int ret = sfn_addnum(di);

	if (ret != 0)
		return ret;

	/* allocate cluster for new DIR */
	if (di->directory & DIRENT_CREAT_DIR) {
		clst = clst_alloc(fs, 0);
		if (invalid_clst(clst)) {
			FMSG("clst_alloc failed\n");
			return -ENOSPC;
		}
	}

	/* fill entry information in parent DIR */
	ret = dirent_alloc(di);
	if (ret != 0) {
		clst_free(fs, clst, 0);
		FMSG("ldir alloc failed %d\n", ret);
		return ret;
	}
	/* fill entry information in parent DIR */
	dirent_fill(di);

	/* register for new DIR */
	if (di->directory & DIRENT_CREAT_DIR)
		dir_register(di, clst);

	return 0;
}

static void file_fi(struct d_info *di, struct f_info *fi)
{
	fi->fs = di->fs;
	fi->flags = di->flags;
	fi->dir = di->dir;
	fi->sclst = clst_get(di->fs, di->dir);
	fi->clst = fi->sclst;
	fi->offset = 0;
	fi->hole = 0;

	get_lock(di->fs, fi);
}

static void file_append(struct f_info *fi)
{
	struct fatfs *fs = fi->fs;
	off_t off = fi->dir->filesize;
	int clst = fi->sclst;

	while (off > 0) {
		off -= fs->cbytes;
		clst = off > 0 ? fatent_get(fs, clst) : clst;
	}
	fi->clst = clst;
	fi->offset = fi->dir->filesize;
}

static void file_trunc(struct f_info *fi)
{
	struct fatfs *fs = fi->fs;

	if (fi->dir->filesize) {
		struct direnty *dir = fi->dir;

		dir->filesize = 0;
		fatfs_update_time(&dir->date, &dir->time);
		dir->cdate = dir->date;
		dir->ctime = dir->time;
		clst_free(fs, fi->sclst, 0);
		clst_set(fs, dir, 0);
		fi->sclst = 0;
		fi->clst = 0;
		fi->offset = 0;
		fi->hole = 0;
	}
}

static int file_create(struct file *f,
	struct d_info *di, struct f_info *fi, mode_t mode)
{
	int ret = -EPERM;
	int flags = f->flags;

	if ((flags & O_CREAT) == 0)
		return -ENOENT;

	if (di->directory)
		return -EISDIR;

	if (flags & O_DIRECTORY)
		return -ENOTDIR;

	di->flags = flags;
	di->mode = mode;

	fi->lock = alloc_lock(di->fs, NULL);
	if (fi->lock == NULL)
		return -ENOMEM;

	ret = dirent_register(di);
	if (ret != 0) {
		put_lock(di->fs, fi);
		return ret;
	}

	file_fi(di, fi);

	return ret;
}

static int file_open(struct file *f,
	struct d_info *di, struct f_info *fi)
{
	int ret = -EPERM;
	int flags = f->flags;
	int wrflag = flags & O_ACCMODE;
	struct direnty *dir = di->dir;

	/* O_EXCL always alongside O_CREAT ? */
	if (flags & O_EXCL)
		return -EEXIST;

	if (dir->attr & ATTR_DIR) {
		if (flags & (O_ACCMODE | O_CREAT))
			return -EISDIR;

		if (flags & (O_TRUNC | O_APPEND))
			return -EISDIR;

		f->flags |= O_DIRECTORY;
	} else if (di->directory | (flags & O_DIRECTORY))
		return -ENOTDIR;

	if (wrflag && (dir->attr & ATTR_RO))
		return -EACCES;

	ret = chk_cached_lock(di->fs, dir);
	if (ret != 0)
		return ret;

	fi->lock = alloc_lock(di->fs, dir);
	if (fi->lock == NULL)
		return -ENOMEM;

	di->flags = f->flags;

	file_fi(di, fi);

	if (wrflag && (flags & O_TRUNC))
		file_trunc(fi);

	return 0;
}

static int fat_open(struct file *f, mode_t mode, void *arg)
{
	int ret = -1;
	struct fatfs *fs = file2fatfs(f);
	struct d_info _di, *di = &_di;
	struct f_info *fi = NULL;

	fi = kzalloc(sizeof(struct f_info));
	if (fi == NULL)
		return -ENOMEM;

	memset(di, 0, sizeof(struct d_info));

	INIT_LIST_HEAD(&fi->node);

	lock_fatfs(fs);
	di->fs = fs;
	ret = follow_path(di, f->path);

	if (di->abort || (ret == -ENAMETOOLONG))
		goto out;

	if (ret == 0)
		ret = file_open(f, di, fi);
	else if (ret == -ENOENT)
		ret = file_create(f, di, fi, mode);

	f->priv = fi;

out:
	unlock_fatfs(fs);
	if (ret != 0)
		kfree(fi);
	return ret;
}

static int fat_close(struct file *f)
{
	struct f_info *fi = f->priv;
	struct fatfs *fs = file2fatfs(f);

	if (fi == NULL)
		return -EBADF;

	lock_fatfs(fs);

	if (f->flags & O_ACCMODE) {
		fi->offset = 0;
		free_seekhole(fi);
	}

	put_lock(fs, fi);

	unlock_fatfs(fs);

	kfree(fi);

	return 0;
}

static ssize_t fat_read(struct file *f, void *buf, size_t cnt)
{
	char *mem = NULL;
	off_t rd_off = 0, clst = 0;
	size_t rd_bytes = 0, unalign = 0, remain = 0;
	struct f_info *fi = f->priv;
	struct fatfs *fs = file2fatfs(f);

	if (fi == NULL)
		return -EBADF;

	if (cnt == 0)
		return 0;

	if (buf == NULL)
		return -EINVAL;

	lock_fatfs(fs);

	if (fi->dir->filesize <= (size_t)fi->offset)
		goto out;

	remain = min(cnt, (size_t)(fi->dir->filesize - fi->offset));

	FMSG("clst %d offset 0x%x\n", fi->clst, fi->offset);

	clst = fi->clst;
	while (remain) {
		unalign = fi->offset % fs->cbytes;

		if (fi->offset && !unalign) {
			clst = fatent_get(fs, clst);
			if (invalid_clst(clst))
				goto out;
			fi->clst = clst;
		}

		mem = clst2mem(fs, clst);
		if (mem == NULL)
			goto out;

		rd_bytes = min((size_t)fs->cbytes - unalign, remain);
		memcpy(buf + rd_off, mem + unalign, rd_bytes);

		FMSG("clst %d @ %p %d\n", (int)clst,
			(void *)(mem - fs->membase), (int)unalign);

		remain -= rd_bytes;
		rd_off += rd_bytes;
		fi->offset += rd_bytes;
	}

out:
	if (rd_off > 0)
		fatfs_update_time(&fi->dir->adate, NULL);

	unlock_fatfs(fs);
	return rd_off;
}

static ssize_t fat_write(struct file *f, const void *buf, size_t cnt)
{
	ssize_t wr_off = 0;
	size_t wr_bytes = 0, unalign = 0;
	struct f_info *fi = f->priv;
	struct fatfs *fs = file2fatfs(f);
	char *mem = NULL;
	int clst = 0;

	if (fi == NULL)
		return -EBADF;

	if (cnt == 0)
		return 0;

	if (buf == NULL)
		return -EINVAL;

	lock_fatfs(fs);

	if (f->flags & O_APPEND) {
		file_append(fi);
		free_seekhole(fi);
		fi->hole = 0;
	}

	if (fi->sclst == 0) {
		clst = clst_alloc(fs, 0);
		if (invalid_clst(clst))
			goto out;

		fi->sclst = clst;
		fi->clst = clst;
		clst_set(fs, fi->dir, clst);
	}

	clst = fi->clst;
	while (cnt) {
		unalign = fi->offset % fs->cbytes;
		if (fi->offset && !unalign) {
			clst = clst_alloc(fs, clst);
			if (invalid_clst(clst))
				goto out;
			fi->clst = clst;
		}

		mem = clst2mem(fs, clst);
		if (mem == NULL)
			goto out;

		wr_bytes = min((size_t)fs->cbytes - unalign, cnt);
		memcpy(mem + unalign, buf + wr_off, wr_bytes);
		cnt -= wr_bytes;
		wr_off += wr_bytes;
		fi->offset += wr_bytes;
	}

out:
	if (wr_off == 0)
		wr_off = -ENOSPC;

	if (wr_off > 0) {
		if (fi->dir->filesize < fi->offset)
			fi->dir->filesize = fi->offset;
		fi->hole = 0;
		fatfs_update_time(&fi->dir->date, &fi->dir->time);
	}
	unlock_fatfs(fs);
	return wr_off;
}

static off_t file_seek(struct f_info *fi, off_t off, int whence)
{
	int wrflag = 0, clst = 0, hole = 0;
	struct fatfs *fs = fi->fs;
	off_t ret = -1, seek = 0;
	struct direnty *dir = fi->dir;

	if (whence == SEEK_CUR)
		off += fi->offset;
	else if (whence == SEEK_END)
		off += (off_t)fi->dir->filesize;
	else if (whence != SEEK_SET)
		return -EINVAL;

	if (off < 0)
		return -EINVAL;

	/* extend cluster chain */
	wrflag = fi->flags & O_ACCMODE;
	if (off > dir->filesize) {
		if (wrflag) {
			hole = calc_seekhole(dir->filesize, fs->cbytes, off);
			if (!clst_enough(fs, hole - fi->hole)) {
				ret = -ENOSPC;
				goto out;
			}
		} else
			off = dir->filesize;
	}

	if (off && wrflag && (fi->sclst == 0)) {
		clst = clst_alloc(fs, 0);
		fi->sclst = clst;
		fi->clst = clst;
		clst_set(fs, dir, clst);
	}

	fi->offset = 0;
	fi->clst = fi->sclst;
	clst = fi->clst;
	while (off) {
		seek = fs->cbytes < off ? fs->cbytes : off;
		off -= seek;
		fi->offset += seek;

		if (off && (fi->offset % fs->cbytes == 0)) {
			clst = wrflag ? clst_alloc(fs, clst)
					 : fatent_get(fs, clst);
			if (invalid_clst(clst))	{
				ret = fi->offset;
				goto out;
			}
			fi->clst = clst;
		}
	}

	ret = fi->offset;

	/* refresh the ceiling of the seek hole */
	if (fi->offset > dir->filesize)
		fi->hole = max(hole, fi->hole);

	/* shrink the superfluous seek holes */
	if (hole < fi->hole) {
		free_seekhole(fi);
		fi->hole = hole;
	}

out:
	return ret;
}

static off_t dir_seek(struct f_info *fi, off_t off, int whence)
{
	if (whence != SEEK_SET)
		return -EINVAL;

	if (off & (sizeof(struct direnty) - 1))
		return -EINVAL;

	fi->offset = off;

	return off;
}

static off_t fat_seek(struct file *f, off_t off, int whence)
{
	off_t ret = -1;
	struct f_info *fi = f->priv;
	struct fatfs *fs = file2fatfs(f);

	if (fi == NULL)
		return -EBADF;

	lock_fatfs(fs);

	if (fi->dir->attr & ATTR_DIR)
		ret = dir_seek(fi, off, whence);
	else
		ret = file_seek(fi, off, whence);

	unlock_fatfs(fs);
	return ret;
}

static int fat_ftruncate(struct file *f, off_t length)
{
	int clst = 0, ret = 0;
	struct f_info *fi = f->priv;
	struct fatfs *fs = file2fatfs(f);
	off_t off = 0, seek = 0;

	if (fi == NULL)
		return -EBADF;

	if (length < 0)
		return -EFBIG;

	lock_fatfs(fs);

	if (length <= fi->dir->filesize) {
		/* shrink cluster chain */
		fi->dir->filesize = length;
		free_seekhole(fi);
	} else {
		/* extend cluster chain */
		clst = fi->clst;
		off = fi->offset;
		seek = file_seek(fi, length, SEEK_SET);
		fi->clst = clst;
		fi->offset = off;
		if (seek < 0) {
			ret = seek;
			goto out;
		}
		fi->dir->filesize = length;
	}

	fi->hole = calc_seekhole(length, fs->cbytes, fi->offset);
	fatfs_update_time(&fi->dir->date, &fi->dir->time);
	fi->dir->cdate = fi->dir->date;
	fi->dir->ctime = fi->dir->time;

out:
	unlock_fatfs(fs);
	return ret;
}

static int fat_fstat(struct file *f, struct stat *st)
{
	struct f_info *fi = f->priv;
	struct fatfs *fs = file2fatfs(f);
	struct direnty *dir = NULL;

	if (fi == NULL)
		return -EBADF;

	if (st == NULL)
		return -EINVAL;

	lock_fatfs(fs);

	dir = fi->dir;
	st->st_size = dir->filesize;
	st->st_blksize = fs->ssize;
	st->st_blocks = dir->filesize / fs->ssize;
	if (dir->filesize % fs->ssize)
		st->st_blocks++;

	if (dir->attr & ATTR_DIR)
		st->st_mode = S_IFDIR;
	else
		st->st_mode = S_IFREG;

	st->st_atime = date2time(1980 + (dir->adate >> 9),
		(dir->adate >> 5) & 0x000F, dir->adate & 0x001F,
		0, 0, 0);

	st->st_mtime = date2time(1980 + (dir->date >> 9),
		(dir->date >> 5) & 0x000F, dir->date & 0x001F,
		 dir->time >> 11, (dir->time >> 5) & 0x003F,
		(dir->time & 0x001F) << 1);

	st->st_ctime = date2time(1980 + (dir->cdate >> 9),
		(dir->cdate >> 5) & 0x000F, dir->cdate & 0x001F,
		 dir->ctime >> 11, (dir->ctime >> 5) & 0x003F,
		(dir->ctime & 0x001F) << 1);

	unlock_fatfs(fs);
	return 0;
}

static int fat_rename(struct file_system *pfs,
	const char *oldpath, const char *newpath)
{
	int ret = -1;
	struct f_lock *l = NULL;
	struct f_info *fi = NULL;
	struct direnty *odir = NULL;
	struct d_info _di, _ndi;
	struct d_info *di = &_di, *ndi = &_ndi;

	if (!newpath || !oldpath)
		return -EINVAL;

	memset(di, 0, sizeof(struct d_info));
	memset(ndi, 0, sizeof(struct d_info));

	di->fs = pfs->priv;
	ndi->fs = di->fs;

	lock_fatfs(di->fs);
	ret = follow_path(di, oldpath);
	if (ret != 0)
		goto out;

	odir = di->dir;

	/* mount point not to be renamed */
	if (odir->attr & ATTR_VOL) {
		ret = -EBUSY;
		goto out;
	}

	if ((odir->attr & ATTR_DIR) &&
		(odir->attr & ATTR_RO)) {
		ret = -EACCES;
		goto out;
	}

	ret = follow_path_exclusion(ndi, newpath, odir);
	if (ret == 0) {
		ret = -EEXIST;
		goto out;
	}

	/* ndi->abort -> parent directory does not exist */
	if (ndi->abort || (ret != -ENOENT))
		goto out;

	if (!(odir->attr & ATTR_DIR) && ndi->directory) {
		ret = -ENOTDIR;
		goto out;
	}

	if (odir->attr & ATTR_DIR)
		ndi->directory = DIRENT_DIR;

	ret = dirent_register(ndi);
	if (ret != 0)
		goto out;

	/* update dirent for each opend f_info */
	l = list_cached_lock(di->fs, odir);
	if (l != NULL) {
		l->dir = ndi->dir;
		list_for_each_entry(fi, &l->files, node)
			fi->dir = ndi->dir;
	}

	memcpy(&ndi->dir->attr, &odir->attr,
		sizeof(struct direnty) - FAT_MAX_SFN);
	dirent_remove(di);

	fatfs_update_time(&ndi->dir->cdate, &ndi->dir->ctime);

out:
	unlock_fatfs(di->fs);
	return ret;
}

static int fat_unlink(struct file_system *pfs, const char *path)
{
	int ret = 0, sclst = 0;
	struct f_lock *l = NULL;
	struct f_info *fi = NULL;
	struct direnty *dir = NULL;
	struct d_info _di, *di = &_di;

	if (!path)
		return -EINVAL;

	memset(di, 0, sizeof(struct d_info));

	di->fs = pfs->priv;

	lock_fatfs(di->fs);

	ret = follow_path(di, path);
	if (ret != 0)
		goto out;

	if (di->directory || (di->dir->attr & ATTR_DIR)) {
		ret = -EISDIR;
		goto out;
	}

	l = list_cached_lock(di->fs, di->dir);
	if (l != NULL) {
		/*
		 * original dir is located in fat,
		 * so we shall not use it anymore, use tmp for read()/write()
		 */
		dir = kmalloc(sizeof(*dir));
		if (dir == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		memcpy(dir, di->dir, sizeof(*dir));
		l->unlink = true;
		l->dir = dir;
		dirent_remove(di);
		list_for_each_entry(fi, &l->files, node)
			fi->dir = dir;
		goto out;
	}

	/* free file content clusters */
	sclst = clst_get(di->fs, di->dir);
	clst_free(di->fs, sclst, 0);
	/* remove filename(fn) in the parent dir */
	dirent_remove(di);

out:
	unlock_fatfs(di->fs);
	return ret;
}

/*
 * read a file name in current DIR
 * return the name length in bytes
 */
static int read_dir(struct d_info *di)
{
	int cnt = 0, ret = 0;
	uint8_t ord = -1, sum = -1;
	uint8_t attr = 0, c = 0;
	struct ldirenty *ldir = NULL;

	ldir = dirent_renew(di, di->offset);
	if (ldir == NULL)
		return -ENOENT;

	do {
		/* end of the dir table */
		c = ldir->ord;
		if (c == 0)
			return -ENOENT;

		attr = ldir->attr & ATTR_MASK;
		if (c != DIRENT_DEM && c != '.') {
			if (attr == ATTR_LFN) {
				/* LFN entry re-started with 0x40 flag */
				if (c & LAST_LONG_ENTRY) {
					sum = ldir->checksum;
					ord = c & LFN_ENTRY_MASK;
					c = ord;
					cnt = 0;
				}

				FMSG("ret=%d, ord=%d, c=%d, sum=%d,lsum=%d, clst %d off 0x%x\n",
					ret, ord, c, sum, ldir->checksum, di->clst, di->offset);

				if ((c == ord) && (sum == ldir->checksum)) {
					ret = lfnget(ldir, di->lfn);
					if (ret > 0) {
						cnt += ret;
						ord -= 1;
					} else
						ord = -1;
				} else
					ord = -1;
			} else {
				FMSG("ord=%d, sum=%d,dsum=%d, clst %d off 0x%x\n",
						ord, sum, sfnsum(di->dir->name),
						di->clst, di->offset);
				if ((ord == 0) && (sum == sfnsum(di->dir->name)))
					return cnt;
				if (ord == 255)
					return sfnget(di->dir, di->lfn);
				ord = -1;
			}
		} else {
			ord = -1;
		}
	} while ((ldir = dirent_next(di, false)) != NULL);

	return -ENOENT;
}

/*
 * read one or multiple object name/type in current DIR
 * return the length in bytes
 */
static ssize_t fat_readdir(struct file *f, struct dirent *d, size_t count)
{
	ssize_t rdbytes = -1, pos = 0;
	ssize_t reclen = 0, dsize = 0;
	struct f_info *fi = f->priv;
	struct d_info _di, *di = &_di;
	struct fatfs *fs = file2fatfs(f);

	if (fi == NULL)
		return -EBADF;

	if (d == NULL)
		return -EINVAL;

	lock_fatfs(fs);
	di->fs = fs;
	di->sclst = fi->sclst;
	di->offset = fi->offset;
	dsize = sizeof(d->d_type) + sizeof(d->d_reclen) + sizeof(d->d_off);

	FMSG("sclst %d offset 0x%x\n", di->sclst, di->offset);

	while ((rdbytes = read_dir(di)) > 0) {
		reclen = roundup(rdbytes + dsize, (ssize_t)BYTES_PER_LONG);
		if (pos + reclen > count)
			break;

		di->offset += sizeof(struct direnty);

		d->d_off = fi->offset = di->offset;
		d->d_type = (di->dir->attr & ATTR_ARC) ? DT_REG : DT_DIR;
		d->d_reclen = reclen;
		memcpy(d->d_name, di->lfn, rdbytes);
		memset(di->lfn, 0, sizeof(di->lfn));

		pos += reclen;
		d = (void *)d + reclen;
	}

	unlock_fatfs(fs);
	return pos;
}

static int fat_mkdir(struct file_system *pfs, const char *path, mode_t mode)
{
	int ret = -1;
	struct d_info _di, *di = &_di;

	if (!path)
		return -EINVAL;

	memset(di, 0, sizeof(struct d_info));

	di->fs = pfs->priv;

	lock_fatfs(di->fs);

	ret = follow_path(di, path);
	if (ret == 0) {
		ret = -EEXIST;
		goto out;
	}

	/* di->abort -> parent directory does not exist */
	if (di->abort || (ret != -ENOENT))
		goto out;

	di->mode = mode;
	di->directory = DIRENT_CREAT_DIR;
	ret = dirent_register(di);
	if (ret != 0) {
		DMSG("dir register failed %d\n", ret);
		goto out;
	}

out:
	unlock_fatfs(di->fs);
	return ret;
}

static int fat_rmdir(struct file_system *pfs, const char *path)
{
	int ret = -1;
	struct f_lock *l = NULL;
	struct f_info *fi = NULL;
	struct d_info _di, *di = &_di;
	struct d_info _cdi, *cdi = &_cdi;

	if (!path)
		return -EINVAL;

	memset(di, 0, sizeof(struct d_info));

	di->fs = pfs->priv;

	lock_fatfs(di->fs);

	ret = follow_path(di, path);
	if (ret != 0)
		goto out;

	if (!(di->dir->attr & ATTR_DIR)) {
		ret = -ENOTDIR;
		goto out;
	}

	/* mount point is not removable */
	if (di->dir->attr & ATTR_VOL) {
		ret = -EBUSY;
		goto out;
	}

	/* check current DIR empty or not */
	cdi->fs = di->fs;
	cdi->offset = 0;
	cdi->sclst = clst_get(di->fs, di->dir);
	ret = read_dir(cdi);
	if (ret > 0) {
		ret = -ENOTEMPTY;
		goto out;
	}

	ret = 0;

	l = list_cached_lock(di->fs, di->dir);
	if (l != NULL) {
		list_for_each_entry(fi, &l->files, node) {
			fi->offset = 0;
			fi->sclst = -1;
		}
		/* dir is located in fat, so we shall not use it anymore */
		l->dir = NULL;
	}

	/* free current DIR cluster */
	clst_free(di->fs, cdi->sclst, 0);
	/* remove current DIR name in the parent dir */
	dirent_remove(di);

out:
	unlock_fatfs(di->fs);
	return ret;
}

static const struct file_operations fatfs_ops = {
	.open = fat_open,
	.close = fat_close,
	.read = fat_read,
	.write = fat_write,
	.mmap = NULL,
	.ioctl = NULL,
	.poll = NULL,

	.lseek = fat_seek,
	.ftruncate = fat_ftruncate,
	.fstat = fat_fstat,
	.rename = fat_rename,
	.unlink = fat_unlink,

	.readdir = fat_readdir,
	.mkdir = fat_mkdir,
	.rmdir = fat_rmdir,
};

static size_t fat_getfree(struct file_system *pfs)
{
	struct fatfs *fs = pfs->priv;

	return (size_t)fs->free_clst * fs->cbytes;
}

int fat_umount(struct file_system *pfs)
{
	struct fatfs *fs = pfs->priv;

	assert(list_empty(&fs->llocks));

	mutex_destroy(&fs->lock);

	pfs->fops = NULL;
	pfs->priv = NULL;

	kfree(fs);

	return 0;
}

int fat_mount(struct file_system *pfs)
{
	int is_fat32 = false;
	int size = 0, dirs_persec = 0, total_sec = 0;
	int resvd = 0, data_sec = 0, sys_sec = 0;
	int data_clst = 0;
	struct fatfs __fs, *fs = &__fs;
	char *fsi_sec = NULL;
	static const char * const fat_type[] = {
		"None", "FAT12", "FAT16", "FAT32"
	};
	char *img = pfs->mnt.addr;
	size_t img_size = pfs->mnt.size;

	if (load8h(img + BS_JMPBOOT) != 0xEB && load8h(img + BS_JMPBOOT) != 0xE9)
		return -EINVAL;

	if (load16h(img + BS_BOOTSIG) != 0xAA55)
		return -EINVAL;

	if (!memcmp(img + BS_OEMNAME, "EXFAT   ", 8))
		return -ENOTSUP;

	memset(fs, 0, sizeof(struct fatfs));

	fs->membase = img;
	fs->memsize = img_size;

	/*
	 * number of bytes per sector
	 */
	size = load16h(img + BPB_BYTSPERSEC);
	if (invalid_ss(size))
		return -ENOTSUP;
	fs->ssize = size;

	/*
	 * number of sectors per cluster
	 */
	size = load8h(img + BPB_SECPERCLUS);
	if (size == 0 || (size & (size - 1)))
		return -EINVAL;
	fs->csize = size;
	fs->cbytes = size * fs->ssize;

	/*
	 * number of sectors per FAT
	 */
	size = load16h(img + BPB_FATSZ16);
	if (size == 0) {
		is_fat32 = true;
		size = load32h(img + BPB_FATSZ32);
	}
	if (size == 0)
		return -EINVAL;
	fs->fsize = size;

	total_sec = load16h(img + BPB_TOTSEC16);
	if (total_sec == 0)
		total_sec = load32h(img + BPB_TOTSEC32);

	if ((size_t)total_sec * fs->ssize != img_size)
		return -EINVAL;

	/*
	 * number of FAT - must be 1 or 2
	 */
	size = load8h(img + BPB_NUMFATS);
	if (size != 1 && size != 2)
		return -EINVAL;
	fs->nr_fats = size;

	/*
	 * number of root directories
	 */
	size = load16h(img + BPB_ROOTENTCNT);
	dirs_persec = fs->ssize / sizeof(struct ldirenty);
	if (size % dirs_persec)
		return -EINVAL;
	fs->nr_rdirent = size;

	/*
	 * number of reserved sectors
	 */
	resvd = load16h(img + BPB_RSVDSECCNT);
	if (resvd == 0)
		return -EINVAL;

	fs->volbase = 0;
	fs->fatbase = fs->volbase + resvd;

	/*
	 * FirstDataSector = BPB_ResvdSecCnt + (BPB_NumFATs * FATSz) + RootDirSectors;
	 */
	sys_sec = resvd + fs->fsize * fs->nr_fats + fs->nr_rdirent / dirs_persec;
	fs->database = fs->volbase + sys_sec;

	data_sec = total_sec - sys_sec;
	data_clst = data_sec / fs->csize;
	if (is_fat32 || (fs->nr_rdirent == 0)) {
		if (load16h(img + BPB_FSVER32) != 0 || fs->nr_rdirent != 0)
			return -EINVAL;
		if (strncmp(img + BS_FILSYSTYPE32, "FAT32   ", 8) == 0)
			fs->type = FAT32;
		fs->dirbase = load32h(img + BPB_ROOTCLUS32);
	} else {
		if (fs->nr_rdirent == 0)
			return -EINVAL;
		if ((data_clst < FAT12_CLUSTER) ||
			(strncmp(img + BS_FILSYSTYPE, "FAT12   ", 8) == 0))
			fs->type = FAT12;
		else if ((data_clst < FAT16_CLUSTER) ||
			(strncmp(img + BS_FILSYSTYPE, "FAT16   ", 8) == 0))
			fs->type = FAT16;
		fs->dirbase = fs->fatbase + fs->fsize * fs->nr_fats;
	}

	if (fs->type == 0) {
		EMSG("invalid fat header\n");
		return -EINVAL;
	}

	fs->nr_fatent = data_clst + 2;

	fs->last_clst = 0xFFFFFFFF;
	fs->free_clst = 0xFFFFFFFF;
	if ((fs->type == FAT32) && (load16h(img + BPB_FSINFO32) == 1)) {
		fsi_sec = sect2mem(fs, FSI_SECBASE);
		if (load32h(fsi_sec + FSI_LEADSIG) == 0x41615252 &&
			load32h(fsi_sec + FSI_STRUCSIG) == 0x61417272) {
			fs->fsi_sec = fsi_sec;
			fs->free_clst = load32h(fsi_sec + FSI_FREE_CLST);
			fs->last_clst = load32h(fsi_sec + FSI_LAST_CLST);
		}
	}

	if (fs->free_clst == 0xFFFFFFFF)
		fs->free_clst = nr_freeclst(fs);

	memset(&fs->root, 0, sizeof(fs->root));
	fs->root.attr = ATTR_DIR | ATTR_RO | ATTR_VOL;

	/* root directory does not have date/time, just set to current time */
	fatfs_update_time(&fs->root.cdate, &fs->root.ctime);
	fatfs_update_time(&fs->root.date, &fs->root.time);

	LMSG("ssize %d, csize %d, fsize %d, nr_fats %d, total_sec %d\n",
			fs->ssize, fs->csize, fs->fsize,
			fs->nr_fats, total_sec);
	LMSG("nr_rdirent %d, resvd %d, sys_sec %d, data_sec %d, data_clst %d\n",
			fs->nr_rdirent, resvd, sys_sec,
			data_sec, data_clst);
	LMSG("volbase %d, fatbase %d, database %d, dirbase %d, nr_fatent %d, type %s\n",
			fs->volbase, fs->fatbase, fs->database, fs->dirbase,
			fs->nr_fatent, fat_type[fs->type]);
	LMSG("free_clst %d, last_clst %d\n",
		fs->free_clst, fs->last_clst);

	fs = kmalloc(sizeof(struct fatfs));
	if (fs == NULL)
		return -ENOMEM;

	memcpy(fs, &__fs, sizeof(struct fatfs));

	INIT_LIST_HEAD(&fs->llocks);
	mutex_init(&fs->lock);
	pfs->fops = &fatfs_ops;
	pfs->priv = fs;
	pfs->type = fat_type[fs->type] /* fatfs */;
	pfs->getfree = fat_getfree;

	return 0;
}
