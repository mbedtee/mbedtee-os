/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * FAT FS private macros
 */

#ifndef _FATFS_PRIV_H
#define _FATFS_PRIV_H

#include <list.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define BS_JMPBOOT			0
#define BS_OEMNAME			3
#define BPB_BYTSPERSEC		11
#define BPB_SECPERCLUS		13
#define BPB_RSVDSECCNT		14
#define BPB_NUMFATS			16
#define BPB_ROOTENTCNT		17
#define BPB_TOTSEC16		19
#define BPB_MEDIA			21
#define BPB_FATSZ16			22
#define BPB_SECPERTRK		24
#define BPB_NUMHEADS		26
#define BPB_HIDDSEC			28
#define BPB_TOTSEC32		32
#define BS_DRVNUM			36
#define BS_NTRES			37
#define BS_BOOTSIGEXT		38
#define BS_VOLID			39
#define BS_VOLLAB			43
#define BS_FILSYSTYPE		54
#define BS_BOOTCODE			62
#define BS_BOOTSIG			510

#define BPB_FATSZ32			36		/* FAT32: FAT size [sector] (DWORD) */
#define BPB_EXTFLAGS32		40		/* FAT32: Extended flags (WORD) */
#define BPB_FSVER32			42		/* FAT32: Filesystem version (WORD) */
#define BPB_ROOTCLUS32		44		/* FAT32: Root directory cluster (DWORD) */
#define BPB_FSINFO32		48		/* FAT32: Offset of FSINFO sector (WORD) */
#define BPB_BKBOOTSEC32		50		/* FAT32: Offset of backup boot sector (WORD) */
#define BS_DRVNUM32			64		/* FAT32: Physical drive number for int13h (BYTE) */
#define BS_NTRES32			65		/* FAT32: Error flag (BYTE) */
#define BS_BOOTSIG32		66		/* FAT32: Extended boot signature (BYTE) */
#define BS_VOLID32			67		/* FAT32: Volume serial number (DWORD) */
#define BS_VOLLAB32			71		/* FAT32: Volume label string (8-byte) */
#define BS_FILSYSTYPE32		82		/* FAT32: Filesystem type string (8-byte) */
#define BS_BOOTCODE32		90		/* FAT32: Boot code (420-byte) */

#define FSI_SECBASE			1

#define FSI_LEADSIG			0		/* FAT32 FSI: Leading signature (DWORD) */
#define FSI_STRUCSIG		484		/* FAT32 FSI: Structure signature (DWORD) */
#define FSI_FREE_CLST		488		/* FAT32 FSI: Number of free clusters (DWORD) */
#define FSI_LAST_CLST		492		/* FAT32 FSI: Last allocated cluster (DWORD) */

#define DIR_Name			0		/* Short file name (11-byte) */
#define DIR_Attr			11		/* Attribute (BYTE) */
#define DIR_NTres			12		/* Lower case flag (BYTE) */
#define DIR_CrtTime10		13		/* Created time sub-second (BYTE) */
#define DIR_CrtTime			14		/* Created time (DWORD) */
#define DIR_LstAccDate		18		/* Last accessed date (WORD) */
#define DIR_FstClusHI		20		/* Higher 16-bit of first cluster (WORD) */
#define DIR_ModTime			22		/* Modified time (DWORD) */
#define DIR_FstClusLO		26		/* Lower 16-bit of first cluster (WORD) */
#define DIR_FileSize		28		/* File size (DWORD) */

#define LDIR_Ord			0		/* LFN: LFN order and LLE flag (BYTE) */
#define LDIR_Attr			11		/* LFN: LFN attribute (BYTE) */
#define LDIR_Type			12		/* LFN: Entry type (BYTE) */
#define LDIR_Chksum			13		/* LFN: Checksum of the SFN (BYTE) */
#define LDIR_FstClusLO		26		/* LFN: MBZ field (WORD) */

#define LAST_LONG_ENTRY		0x40
#define LFN_ENTRY_MASK		0x3F
#define LDIR_NAME_BYTES		13

#define ATTR_RO			0x01
#define ATTR_HID			0x02
#define ATTR_SYS			0x04
#define ATTR_VOL			0x08
#define ATTR_DIR			0x10
#define ATTR_ARC			0x20
#define ATTR_LFN			0x0F
#define ATTR_MASK			0x3F

#define DIRENT_DEM			0xE5

#define DIRENT_ARC			(0l << 0)
#define DIRENT_DIR			(1l << 0)
#define DIRENT_CREAT_DIR	(1l << 1)

#define FN_IS_LFN			(1l << 0)
#define FN_LOWER_NAME		(1l << 3)
#define FN_LOWER_EXT		(1l << 4)

#define FAT12_CLUSTER		4085
#define FAT16_CLUSTER		65525

#define FAT12				1
#define FAT16				2
#define FAT32				3

#define FAT_MAX_LFN			255
#define FAT_SFN_NAME		8
#define FAT_SFN_EXT			3
#define FAT_MAX_SFN			(FAT_SFN_NAME + FAT_SFN_EXT)

#define LOCK_MAX_REFC		(INT_MAX)

struct f_lock {
	int refc;
	bool unlink; /* for unlink file */
	bool freefn; /* for rmdir */

	struct direnty *dir;

	/* node entry in the cached-lock-list */
	struct list_head node;
	/* opened f_info on this lock */
	struct list_head files;
};

struct direnty {
	char name[FAT_SFN_NAME];
	char ext[FAT_SFN_EXT];
	uint8_t attr;
	uint8_t ntres;
	uint8_t ctime_ms;
	uint16_t ctime; /* last status change time */
	uint16_t cdate; /* last status change date */
	uint16_t adate; /* last access date */
	uint16_t starthi;
	uint16_t time; /* last write time */
	uint16_t date; /* last write date */
	uint16_t startlo;
	uint32_t filesize;
};

struct ldirenty {
	uint8_t ord;
	char name1[5 * 2];
	uint8_t attr;
	uint8_t reserved;
	uint8_t checksum;
	char name2[6 * 2];
	uint16_t start;
	char name3[2 * 2];
};

struct fatfs {
	char *membase;
	int memsize;

	uint8_t type;
	uint8_t nr_fats;	 /* nr_fats (1 or 2) @ per drive */
	short nr_rdirent; /* (nr*32) nr of root directory entries (FAT12/16) */
	int nr_fatent;	 /* nr_fatent (nr of clusters + 2) */

	short ssize;		/* nr_bytes @ per sector size */
	short csize;		/* nr_sectors @ per cluster  */
	int cbytes;			/* nr_bytes @ per cluster  */
	int fsize;			/* nr_sectors @ per FAT */

	int last_clst;	/* Last allocated cluster */
	int free_clst;	/* Number of free clusters */

	int volbase;		 /* Unused for ramfs -- Volume base sector */
	int fatbase;		 /* FAT base sector */
	int dirbase;		 /* Root directory base sector/cluster */
	int database;		 /* Data base sector */

	struct list_head llocks; /* list of cached locks */

	struct mutex lock;	/* exclusion access */

	char *fsi_sec;
	struct direnty root; /* dirent for root @ / */
};

struct d_info {
	int sclst;
	int clst;
	int sect;

	int flags; /* open flag */
	mode_t mode; /* create mode */

	uint8_t directory;
	uint8_t fn_flag;
	uint8_t fn_case;
	uint8_t abort;

	int fn_size;
	int fn_start;

	int offset;

	char sfn[FAT_MAX_SFN + 1];
	char lfn[FAT_MAX_LFN + 1];
	struct ldirenty *ldir;
	struct direnty *dir;
	struct fatfs *fs;
};

struct f_info {
	struct fatfs *fs;
	int sclst; /* cluster chain starter */
	int clst; /* current cluster */
	int hole; /* seek hole clusters beyond file size*/

	int flags; /* open flag */

	int offset; /* current file offset */

	struct direnty *dir; /* file @ which dir */
	struct f_lock *lock; /* read/write collide detection */
	struct list_head node; /* node in a cached-lock */
};

static inline uint8_t load8h(void *x)
{
	return *(__volatile uint8_t *)x;
}

static inline uint16_t load16h(void *x)
{
	uint16_t c = load8h(x + 1);

	return (c << 8) | load8h(x);
}

static inline uint32_t load32h(void *x)
{
	uint32_t c = load16h(x + 2);

	return (c << 16) | load16h(x);
}

static inline void store8h(uint8_t c, void *x)
{
	*(__volatile uint8_t *)x = c;
}

static inline void store16h(uint16_t c, void *x)
{
	store8h(c, x);
	store8h(c >> 8, x + 1);
}

static inline void store32h(uint32_t c, void *x)
{
	store16h(c, x);
	store16h(c >> 16, x + 2);
}

#define invalid_ss(x) ((x) != 512 && (x) != 1024 && (x) != 2048 && (x) != 4096)
#define invalid_clst(x) (((x) < 2) || ((x) >= fs->nr_fatent))
#define invalid_rootdir(x) ((x)/sizeof(struct direnty) >= fs->nr_rdirent)

#ifdef __cplusplus
}
#endif
#endif
