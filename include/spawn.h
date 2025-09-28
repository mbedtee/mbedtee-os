/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * Minimal POSIX spawn interface.
 *
 * Note: This header provides POSIX-compatible APIs (posix_spawn* and
 * posix_spawn_file_actions*). The underlying file-actions object is an
 * opaque struct with an internal serialized representation.
 */

#ifndef _SPAWN_H
#define _SPAWN_H

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keep this modest; pipelines/redirections are small. */
#define POSIX_SPAWN_FILE_ACTIONS_MAX 512

typedef struct {
	size_t used;
	unsigned char buf[POSIX_SPAWN_FILE_ACTIONS_MAX];
} posix_spawn_file_actions_t;

/*
 * Internal serialized file-actions format.
 * Shared between user implementation (user/syscall/spawn.c) and kernel spawn
 * implementation (core/syscall/spawn.c).
 */
#define MTEE_SPAWN_ACT_CLOSE 1
#define MTEE_SPAWN_ACT_DUP2  2
#define MTEE_SPAWN_ACT_OPEN  3

struct mtee_spawn_rec_hdr {
	uint16_t type;
	uint16_t reserved;
	uint32_t len; /* total record length including this header */
} __attribute__((packed));

struct mtee_spawn_rec_close {
	struct mtee_spawn_rec_hdr h;
	int32_t fd;
} __attribute__((packed));

struct mtee_spawn_rec_dup2 {
	struct mtee_spawn_rec_hdr h;
	int32_t fd;
	int32_t newfd;
} __attribute__((packed));

struct mtee_spawn_rec_open_fixed {
	struct mtee_spawn_rec_hdr h;
	int32_t fd;
	int32_t oflag;
	int32_t mode;
	uint32_t path_len;
} __attribute__((packed));

/* Attribute object is currently accepted but ignored (must be NULL). */
typedef struct {
	int _unused;
} posix_spawnattr_t;

int posix_spawn(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *file_actions,
	const posix_spawnattr_t *attrp,
	char *const argv[],
	char *const envp[]);

int posix_spawnp(pid_t *pid, const char *file,
	const posix_spawn_file_actions_t *file_actions,
	const posix_spawnattr_t *attrp,
	char *const argv[],
	char *const envp[]);

int posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions);
int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *file_actions);

int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *file_actions,
	int fd);

int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *file_actions,
	int fd, int newfd);

int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *file_actions,
	int fd, const char *path, int oflag, mode_t mode);

#ifdef __cplusplus
}
#endif

#endif
