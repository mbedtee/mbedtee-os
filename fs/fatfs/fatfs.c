// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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
	return f->fs->priv;
}

static inline int clst_get(struct fatfs *fs,
	struct direnty *dir)
{
	if (fs->type == FAT32)
		return ((unsigned int)dir->starthi << 16) | dir->startlo;
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
	if ((unsigned int)sect >= fs->total_sec)
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

	return i + 1;
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

	if (clst != 0) {
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
	if (tclst != 0 && (nclst == sclst))
		return -ENOSPC;

	fatent_set(fs, nclst, -1);
	if (clst != 0)
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

static struct f_inode *find_inode_by_clst(struct fatfs *fs,
	int clst)
{
	struct f_inode *inode = NULL, *n = NULL;

	/* check the cached inode list */
	list_for_each_entry(n, &fs->inodes, node) {
		if (n->dir && (clst_get(fs, n->dir) == clst)) {
			inode = n;
			break;
		}
	}

	return inode;
}

static void fnclst_free(struct fatfs *fs,
	int sclst, int fnstart)
{
	struct ldirenty *ldir = NULL;
	int num = fs->cbytes / sizeof(struct ldirenty), n = 0;
	int prev = sclst, clst = 0, next = 0;
	off_t off = rounddown(fnstart, fs->cbytes);
	struct f_inode *inode = NULL;

	if ((prev == 0) && (fs->type == FAT32))
		prev = fs->dirbase;

	if (!invalid_clst(prev)) {
		inode = find_inode_by_clst(fs, prev);
		if (inode) {
			/*
			 * parent dir was opened,
			 * postpone the free to parent dir close()
			 */
			inode->freefn = true;
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

static struct f_inode *find_inode(struct fatfs *fs,
	struct direnty *dir)
{
	struct f_inode *inode = NULL, *n = NULL;

	if (!dir)
		return NULL;

	/* check the cached inode list */
	list_for_each_entry(n, &fs->inodes, node) {
		if (n->dir == dir) {
			inode = n;
			break;
		}
	}
	return inode;
}

static int chk_inode(struct fatfs *fs,
	struct direnty *dir)
{
	struct f_inode *inode = find_inode(fs, dir);

	/* check the cached inode list */
	if (inode) {
		if (inode->unlink)
			return -ENOENT;

		if (inode->refc + 1 == INODE_MAX_REFC)
			return -EMFILE;
	}

	return 0;
}

static struct f_inode *alloc_inode(struct fatfs *fs,
	struct direnty *dir)
{
	struct f_inode *inode = NULL;

	inode = find_inode(fs, dir);
	if (!inode) {
		inode = kzalloc(sizeof(struct f_inode));
		if (inode) {
			INIT_LIST_HEAD(&inode->files);
			INIT_LIST_HEAD(&inode->node);
		}
	}

	return inode;
}

static void get_inode(struct fatfs *fs, struct f_info *fi)
{
	struct f_inode *inode = fi->inode;

	inode->refc++;
	inode->dir = fi->dir;
	list_add_tail(&fi->node, &inode->files);

	if (list_empty(&inode->node))
		list_add_tail(&inode->node, &fs->inodes);
}

static void put_inode(struct fatfs *fs, struct f_info *fi)
{
	struct f_inode *inode = fi->inode;

	list_del(&fi->node);

	if (--inode->refc <= 0) {
		list_del(&inode->node);

		if (inode->unlink) { /* free clsts of file content */
			clst_free(fs, inode->sclst, 0);
			kfree(inode->dir);
		}

		if (inode->freefn) /* free clsts of dir's file name */
			fnclst_free(fs, inode->sclst, 0);

		kfree(inode);
	}
}

/*
 * Free clusters beyond the file's recorded size.
 * Ensures the cluster chain matches the filesize.
 */
static void clst_truncate(struct f_info *fi)
{
	int clst = fi->inode->sclst;
	struct fatfs *fs = fi->fs;
	off_t off = fi->dir->filesize;

	if (off == 0) {
		if (clst != 0) {
			clst_free(fs, clst, 0);
			clst_set(fs, fi->dir, 0);
			fi->inode->sclst = 0;
		}
		return;
	}

	if (clst == 0)
		return;

	while (off > (off_t)fs->cbytes) {
		off -= fs->cbytes;
		clst = fatent_get(fs, clst);
		if (invalid_clst(clst))
			return;
	}

	clst_free(fs, fatent_get(fs, clst), clst);
}

/*
 * Extend the cluster chain to cover the given offset.
 * Returns 0 on success, negative errno on failure.
 */
static int clst_extend(struct f_info *fi, off_t off)
{
	int clst = 0;
	struct fatfs *fs = fi->fs;
	struct direnty *dir = fi->dir;
	off_t seek = 0, end = 0;

	if (off <= (off_t)dir->filesize)
		return 0;

	end = roundup(dir->filesize, (uint32_t)fs->cbytes);

	if ((off > end) && !clst_enough(fs, roundup(off - end,
		(off_t)fs->cbytes) / fs->cbytes))
		return -ENOSPC;

	if (fi->inode->sclst == 0) {
		clst = clst_alloc(fs, 0);
		if (invalid_clst(clst))
			return -ENOSPC;
		fi->inode->sclst = clst;
		fi->clst = clst;
		clst_set(fs, dir, clst);
	}

	fi->offset = 0;
	fi->clst = fi->inode->sclst;
	clst = fi->clst;
	while (off != 0) {
		seek = min((off_t)fs->cbytes, off);
		off -= seek;
		fi->offset += seek;

		if (off != 0 && (fi->offset % fs->cbytes == 0)) {
			clst = clst_alloc(fs, clst);
			if (invalid_clst(clst))
				return -ENOSPC;
			fi->clst = clst;
		}
	}

	return 0;
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
		if (di->clst != 0 && ((off & (fs->cbytes - 1)) == 0)) {
			clst = fatent_get(fs, di->clst);
			if (invalid_clst(clst)) {
				if (!grow)
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

	if (off != 0 && clst != 0) {
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
	if (!mem)
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
		if (di->sclst != 0 || di->offset != 0)
			return -ENOENT;
		di->dir = &di->fs->root;
		return 0;
	}

	ldir = dirent_renew(di, 0);
	if (!ldir)
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
		} while (num != 0);
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
	if (ldir) {
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
	if (ldir) {
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

	while (ldir && --num != 0) {
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
	if (!dir)
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
	if (!ldir)
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

static off_t file_seek(struct f_info *fi, off_t off, int whence)
{
	struct fatfs *fs = fi->fs;
	struct direnty *dir = fi->dir;
	off_t ret = -1;
	off_t seek = 0;
	int clst = 0;

	if (whence == SEEK_CUR)
		off += fi->offset;
	else if (whence == SEEK_END)
		off += dir->filesize;
	else if (whence != SEEK_SET)
		return -EINVAL;

	if (off < 0)
		return -EINVAL;

	if (off > (off_t)dir->filesize) {
		fi->offset = off;
		return off;
	}

	/*
	 * For off <= EOF we must also update fi->clst, because read()/write()
	 * uses fi->clst as the starting cluster for the current offset.
	 */
	fi->offset = 0;
	fi->clst = fi->inode->sclst;
	clst = fi->clst;

	while (off != 0) {
		seek = min((off_t)fs->cbytes, off);
		off -= seek;
		fi->offset += seek;

		if (off != 0 && (fi->offset % fs->cbytes == 0)) {
			clst = fatent_get(fs, clst);
			if (invalid_clst(clst)) {
				ret = fi->offset;
				goto out;
			}
			fi->clst = clst;
		}
	}

	ret = fi->offset;

out:
	return ret;
}

static void file_fi(struct d_info *di, struct f_info *fi)
{
	fi->fs = di->fs;
	fi->flags = di->flags;
	fi->dir = di->dir;
	fi->offset = 0;

	get_inode(di->fs, fi);

	fi->inode->sclst = clst_get(di->fs, di->dir);
	fi->clst = fi->inode->sclst;
}

static void file_append(struct f_info *fi)
{
	struct fatfs *fs = fi->fs;
	off_t off = fi->dir->filesize;
	int clst = fi->inode->sclst;

	if (fi->offset == off && fi->clst != 0)
		return;

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

	if (fi->dir->filesize != 0) {
		struct direnty *dir = fi->dir;
		struct f_info *tmp = NULL;

		dir->filesize = 0;
		fatfs_update_time(&dir->date, &dir->time);
		dir->cdate = dir->date;
		dir->ctime = dir->time;
		clst_free(fs, fi->inode->sclst, 0);
		clst_set(fs, dir, 0);
		fi->inode->sclst = 0;
		fi->clst = 0;
		fi->offset = 0;

		list_for_each_entry(tmp, &fi->inode->files, node)
			tmp->clst = 0;
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

	fi->inode = alloc_inode(di->fs, NULL);
	if (!fi->inode)
		return -ENOMEM;

	ret = dirent_register(di);
	if (ret != 0) {
		put_inode(di->fs, fi);
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
	} else if (di->directory || (flags & O_DIRECTORY))
		return -ENOTDIR;

	if (wrflag && (dir->attr & ATTR_RO))
		return -EACCES;

	ret = chk_inode(di->fs, dir);
	if (ret != 0)
		return ret;

	fi->inode = alloc_inode(di->fs, dir);
	if (!fi->inode)
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
	if (!fi)
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

	if (!fi)
		return -EBADF;

	lock_fatfs(fs);

	put_inode(fs, fi);

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

	if (!fi)
		return -EBADF;

	if (cnt == 0)
		return 0;

	if (!buf)
		return -EINVAL;

	lock_fatfs(fs);

	/*
	 * Sync fi->clst with the inode's sclst when reading from offset 0.
	 * sclst lives on the inode - always authoritative, even after
	 * truncate+rewrite through another fd.
	 */
	if (fi->offset == 0)
		fi->clst = fi->inode->sclst;
	else if (fi->clst == 0)
		file_seek(fi, fi->offset, SEEK_SET);

	if (fi->dir->filesize <= (size_t)fi->offset)
		goto out;

	remain = min(cnt, (size_t)(fi->dir->filesize - fi->offset));

	FMSG("clst %d offset 0x%x\n", fi->clst, fi->offset);

	clst = fi->clst;
	while (remain) {
		unalign = fi->offset % fs->cbytes;

		if (fi->offset != 0 && unalign == 0) {
			clst = fatent_get(fs, clst);
			if (invalid_clst(clst))
				goto out;
			fi->clst = clst;
		}

		mem = clst2mem(fs, clst);
		if (!mem)
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

/*
 * write(fd, 512) -> ftruncate(fd, 100)
 * ftruncate(fd, 256) -> [100..255] must be zeroed
 */
static void clear_cluster_tail(struct f_info *fi,
	off_t old_size, off_t new_end)
{
	struct fatfs *fs = fi->fs;
	off_t end = 0, until = 0, tmp = 0;
	size_t start = 0, zlen = 0;
	char *mem = NULL;
	int clst = 0;

	if (old_size <= 0)
		return;
	if (new_end <= old_size)
		return;

	start = old_size % fs->cbytes;
	if (start == 0)
		return;

	end = roundup(old_size, (size_t)fs->cbytes);
	until = new_end < end ? new_end : end;
	if (until <= old_size)
		return;

	/* Find the cluster containing old_size. */
	tmp = old_size;
	clst = fi->inode->sclst;
	while (tmp >= (off_t)fs->cbytes) {
		tmp -= (off_t)fs->cbytes;
		clst = fatent_get(fs, clst);
		if (invalid_clst(clst))
			return;
	}

	mem = clst2mem(fs, clst);
	if (!mem)
		return;

	zlen = until - old_size;
	if (zlen != 0)
		memset(mem + start, 0, zlen);
}

static ssize_t fat_write(struct file *f, const void *buf, size_t cnt)
{
	ssize_t wr_off = 0;
	size_t wr_bytes = 0, unalign = 0;
	struct f_info *fi = f->priv;
	struct fatfs *fs = file2fatfs(f);
	char *mem = NULL;
	int clst = 0, old_size = 0;

	if (!fi)
		return -EBADF;

	if (cnt == 0)
		return 0;

	if (!buf)
		return -EINVAL;

	lock_fatfs(fs);

	old_size = fi->dir->filesize;

	if (f->flags & O_APPEND)
		file_append(fi);
	else if (fi->clst == 0) {
		if (fi->offset == 0)
			fi->clst = fi->inode->sclst;
		else
			file_seek(fi, fi->offset, SEEK_SET);
	}

	if (fi->offset > old_size) {
		off_t target = fi->offset;
		if (clst_extend(fi, target) != 0) {
			clst_truncate(fi);
			goto out;
		}

		clear_cluster_tail(fi, old_size, target);
	}

	if (fi->inode->sclst == 0) {
		clst = clst_alloc(fs, 0);
		if (invalid_clst(clst))
			goto out;

		fi->inode->sclst = clst;
		fi->clst = clst;
		clst_set(fs, fi->dir, clst);
	}

	clst = fi->clst;
	while (cnt != 0) {
		unalign = fi->offset % fs->cbytes;
		if (fi->offset != 0 && unalign == 0) {
			clst = clst_alloc(fs, clst);
			if (invalid_clst(clst))
				goto out;
			fi->clst = clst;
		}

		mem = clst2mem(fs, clst);
		if (!mem)
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
		fatfs_update_time(&fi->dir->date, &fi->dir->time);
	}
	unlock_fatfs(fs);
	return wr_off;
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

	if (!fi)
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
	off_t off = 0, old_size = 0;

	if (!fi)
		return -EBADF;

	if (length < 0)
		return -EFBIG;

	lock_fatfs(fs);
	old_size = fi->dir->filesize;

	if (length <= fi->dir->filesize) {
		struct f_info *tmp = NULL;
		/* shrink cluster chain */
		fi->dir->filesize = length;
		clst_truncate(fi);

		list_for_each_entry(tmp, &fi->inode->files, node) {
			if (tmp->offset >= length)
				tmp->clst = 0;
		}
	} else {
		/* extend cluster chain */
		clst = fi->clst;
		off = fi->offset;
		ret = clst_extend(fi, length);
		fi->clst = clst;
		fi->offset = off;
		if (ret != 0) {
			/* rollback: free clusters beyond original size */
			clst_truncate(fi);
			goto out;
		}

		clear_cluster_tail(fi, old_size, length);
		fi->dir->filesize = length;
	}

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

	if (!fi)
		return -EBADF;

	if (!st)
		return -EINVAL;

	lock_fatfs(fs);

	dir = fi->dir;
	st->st_size = dir->filesize;
	st->st_blksize = fs->ssize;

	if (dir->attr & ATTR_DIR) {
		st->st_mode = S_IFDIR;
		st->st_blocks = 1;
	} else {
		st->st_mode = S_IFREG;
		st->st_blocks = dir->filesize / fs->ssize;
		if (dir->filesize % fs->ssize)
			st->st_blocks++;
	}

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

static int file_dir_remove(struct d_info *di)
{
	struct f_inode *inode = NULL;
	struct f_info *fi = NULL;
	struct d_info _cdi, *cdi = &_cdi;
	struct direnty *dir = di->dir, *tdir = NULL;
	int is_dir = dir->attr & ATTR_DIR;
	int ret = -1, sclst = 0;

	/* mount point is not removable */
	if (dir->attr & ATTR_VOL) {
		ret = -EBUSY;
		goto out;
	}

	if (is_dir) {
		/* check current DIR empty or not */
		cdi->fs = di->fs;
		cdi->offset = 0;
		cdi->sclst = clst_get(di->fs, dir);
		ret = read_dir(cdi);
		if (ret > 0) {
			ret = -ENOTEMPTY;
			goto out;
		}
	}

	inode = find_inode(di->fs, di->dir);
	if (inode) {
		if (is_dir) {
			list_for_each_entry(fi, &inode->files, node)
				fi->offset = 0;
			inode->sclst = -1;
			/* dir is located in fat, so we shall not use it anymore */
			inode->dir = NULL;
		} else {
			/*
			 * original dir is located in fat,
			 * so we shall not use it anymore, use tmp for read()/write()
			 */
			tdir = kmalloc(sizeof(*dir));
			if (!tdir) {
				ret = -ENOMEM;
				goto out;
			}

			memcpy(tdir, dir, sizeof(*tdir));
			inode->unlink = true;
			inode->dir = tdir;
			list_for_each_entry(fi, &inode->files, node)
				fi->dir = tdir;
		}
	}

	if (is_dir) /* free current DIR cluster */
		clst_free(di->fs, cdi->sclst, 0);
	else { /* free file content clusters if no opened refc */
		if (!inode) {
			sclst = clst_get(di->fs, dir);
			clst_free(di->fs, sclst, 0);
		}
	}

	/* remove current DIR/File's name in their parent dir */
	dirent_remove(di);

	ret = 0;

out:
	return ret;
}

static int fat_rename(struct file_system *pfs,
	const char *oldpath, const char *newpath)
{
	int ret = -1;
	struct f_inode *inode = NULL;
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

	/* Check source path semantics early */
	ret = follow_path_exclusion(ndi, newpath, odir);

	/* ndi->abort -> parent directory does not exist */
	if (ndi->abort)
		goto out;
	/* If source is file but target path ends with '/', it's invalid */
	if (!(odir->attr & ATTR_DIR) && ndi->directory) {
		ret = -ENOTDIR;
		goto out;
	}

	if (ret == 0) {
		struct direnty *target_dir = ndi->dir;
		int is_dir = target_dir->attr & ATTR_DIR;

		/* POSIX: Cannot rename file over directory or vice versa */
		if ((odir->attr & ATTR_DIR) != is_dir) {
			ret = is_dir ? -EISDIR : -ENOTDIR;
			goto out;
		}

		ret = file_dir_remove(ndi);
		if (ret != 0)
			goto out;

		/*
		 * file_dir_remove(ndi) -> dirent_remove(ndi) -> fnclst_free()
		 *
		 * If the source and destination are in the same directory, and the
		 * destination is removed, the directory cluster chain might be shrunk
		 * (empty cluster reclaimed), which invalidates the offset(fn_start) in old
		 * 'di'. We must refresh 'di' to ensure correct removal of the source later.
		 */
		if (di->sclst == ndi->sclst) {
			memset(di, 0, sizeof(struct d_info));
			di->fs = ndi->fs;
			ret = follow_path(di, oldpath);
			if (ret != 0)
				goto out;
			odir = di->dir;
		}
	}

	if (odir->attr & ATTR_DIR)
		ndi->directory = DIRENT_DIR;

	ret = dirent_register(ndi);
	if (ret != 0)
		goto out;

	/* update dirent for each opened f_info */
	inode = find_inode(di->fs, odir);
	if (inode) {
		inode->dir = ndi->dir;
		list_for_each_entry(fi, &inode->files, node)
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
	int ret = 0;
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

	ret = file_dir_remove(di);

out:
	unlock_fatfs(di->fs);
	return ret;
}

/*
 * read one or multiple object name/type in current DIR
 * return the length in bytes
 */
static ssize_t fat_readdir(struct file *f, struct dirent *d, size_t count)
{
	int err = 0;
	uint8_t type = 0;
	ssize_t rdbytes = -1, init_cnt = count;
	struct f_info *fi = f->priv;
	struct d_info _di, *di = &_di;
	struct fatfs *fs = file2fatfs(f);

	if (!fi)
		return -EBADF;

	if (!d)
		return -EINVAL;

	lock_fatfs(fs);
	di->fs = fs;
	di->sclst = fi->inode->sclst;
	di->offset = fi->offset;

	FMSG("sclst %d offset 0x%x\n", di->sclst, di->offset);

	while ((rdbytes = read_dir(di)) > 0) {
		di->offset += sizeof(struct direnty);

		type = (di->dir->attr & ATTR_DIR) ? DT_DIR : DT_REG;
		err = fs_format_dirent(&d, &count, di->lfn, type, di->offset);
		if (err < 0)
			break;

		fi->offset = di->offset;
		memset(di->lfn, 0, sizeof(di->lfn));
	}

	/* EOF */
	if (rdbytes == -ENOENT)
		rdbytes = 0;

	unlock_fatfs(fs);

	if (rdbytes < 0 && init_cnt == count)
		return rdbytes;

	return init_cnt - count;
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
	struct d_info _di, *di = &_di;

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

	ret = file_dir_remove(di);

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

static void fat_getsize(struct file_system *pfs,
	size_t *total, size_t *idle)
{
	struct fatfs *fs = pfs->priv;

	*total = (size_t)fs->total_sec * fs->ssize;
	*idle = (size_t)fs->free_clst * fs->cbytes;
}

int fat_umount(struct file_system *pfs)
{
	struct fatfs *fs = pfs->priv;

	assert(list_empty(&fs->inodes));

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
	fs->total_sec = total_sec;

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
	if (!fs)
		return -ENOMEM;

	memcpy(fs, &__fs, sizeof(struct fatfs));

	INIT_LIST_HEAD(&fs->inodes);
	mutex_init(&fs->lock);
	pfs->fops = &fatfs_ops;
	pfs->priv = fs;
	pfs->type = fat_type[fs->type] /* fatfs */;
	pfs->getsize = fat_getsize;

	return 0;
}
