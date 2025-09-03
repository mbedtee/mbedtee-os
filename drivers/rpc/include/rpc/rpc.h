/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * RPC wire protocol between REE (Linux) and TEE (MbedTEE OS).
 *
 * All wire-format structures use fixed-width integer types so that
 * sizeof() and offsetof() are identical on 32-bit and 64-bit systems.
 * This allows mixed-width configurations (e.g. RV64 REE + RV32 TEE,
 * or ARM32-LPAE REE + ARM32 TEE) to interoperate correctly.
 *
 * Type policy for wire structs:
 *   uint8_t   -- boolean flag / padding byte
 *   uint16_t  -- byte-count field (< 64 KiB payload limit enforced)
 *   uint32_t  -- 32-bit ID, counter, flag, or enum
 *   int32_t   -- function-defined signed result code
 *   uint64_t  -- physical address, kernel pointer token, or size
 *
 * The Linux-side copy of this header (mbedtee_msg.h) uses Linux kernel
 * type aliases (u8/u16/u32/s32/u64) but must maintain identical layout.
 * Compile-time assertions on both sides enforce this contract.
 */

#ifndef _TEE_RPC_H
#define _TEE_RPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define MBEDTEE_RPC_FASTCALL            (1u << 31)
#define MBEDTEE_RPC_IS_FASTCALL(fn)     ((fn) & MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_FUNC_MASK           (0xFFFF | MBEDTEE_RPC_FASTCALL)

/* REE->TEE Fast calls */
#define MBEDTEE_RPC_VERSION             (0x0000 | MBEDTEE_RPC_FASTCALL) /* PSCI_0_2_FN_PSCI_VERSION */
#define MBEDTEE_RPC_CPU_SUSPEND         (0x0001 | MBEDTEE_RPC_FASTCALL) /* PSCI_0_2_FN_CPU_SUSPEND */
#define MBEDTEE_RPC_CPU_OFF             (0x0002 | MBEDTEE_RPC_FASTCALL) /* PSCI_0_2_FN_CPU_OFF */
#define MBEDTEE_RPC_CPU_ON              (0x0003 | MBEDTEE_RPC_FASTCALL) /* PSCI_0_2_FN_CPU_ON */
#define MBEDTEE_RPC_KILL_SECONDARY      (0x0004 | MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_MIGRATE             (0x0005 | MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_MIGRATE_INFO_TYPE   (0x0006 | MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_MIGRATE_INFO_UP_CPU (0x0007 | MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_SYSTEM_OFF          (0x0008 | MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_SYSTEM_RESET        (0x0009 | MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_SYSTEM_SUSPEND      (0x000E | MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_SET_SUSPEND_MODE    (0x000F | MBEDTEE_RPC_FASTCALL)

#define MBEDTEE_RPC_OS_VERSION          (0x0100 | MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_SUPPORT_YIELD       (0x0101 | MBEDTEE_RPC_FASTCALL)
#define MBEDTEE_RPC_COMPLETE_TEE        (0x0102 | MBEDTEE_RPC_FASTCALL)

/* REE->TEE Yield calls */
#define MBEDTEE_RPC_OPEN_SESSION        1
#define MBEDTEE_RPC_INVOKE_SESSION      2
#define MBEDTEE_RPC_CLOSE_SESSION       3
#define MBEDTEE_RPC_FREE_SHM            4
#define MBEDTEE_RPC_REGISTER_SHM        5
#define MBEDTEE_RPC_UNREGISTER_SHM      6
#define MBEDTEE_RPC_CANCEL              7

/* TEE->REE RPC calls */
#define MBEDTEE_RPC_COMPLETE_REE        0
#define MBEDTEE_RPC_REETIME             1
#define MBEDTEE_RPC_REEFS               2
#define MBEDTEE_RPC_RPMB                3
#define MBEDTEE_RPC_MAX                 4

/* MbedTEE RPC protocol uses 4 KiB page units regardless of host PAGE_SIZE. */
#define MBEDTEE_PAGE_SIZE       (4096UL)

/*
 * REE<->TEE RPC call command (wire format, 32 bytes fixed header).
 *
 * Fixed layout:
 *   +0   id          uint32_t - RPC function identifier
 *   +4   size        uint16_t - inline payload byte count (0..65535)
 *   +6   interrupted uint8_t  - set by REE when caller is interrupted
 *   +7   reserved    uint8_t  - must be zero (explicit alignment pad)
 *   +8   ret         int32_t  - return value written by callee
 *   +12  pad         uint32_t - must be zero (explicit alignment pad)
 *   +16  waiter_id   uint64_t - ID waiting for completion (cookie or thread ID)
 *   +24  shm         uint64_t - phys address of sync-RPC shared memory
 *   +32  data[]      uint64_t - inline payload (waiter_id==0) or empty
 *
 * Yield-call contract:
 *   - Session/control RPCs return GlobalPlatform result codes here.
 *   - Host-local errno values must be translated before being put on the wire.
 *   - Fast calls may use function-specific return values.
 */
struct rpc_cmd {
	uint32_t id;
	uint16_t size;
	uint8_t  interrupted;
	uint8_t  reserved;
	int32_t  ret;
	uint32_t pad;
	uint64_t waiter_id;
	uint64_t shm;
	uint64_t data[];
};

/*
 * REE->TEE pages for GP shared memory.
 *
 * All fields are uint64_t so the layout is identical when REE is 64-bit
 * but TEE is 32-bit (physical addresses, sizes and counts use 64 bits).
 */
struct rpc_memref {
	uint64_t id;
	uint64_t pages;
	uint64_t offset;
	uint64_t size;
	uint64_t cnt;
};

/*
 * REE->TEE parameter entry: value or shared memory reference.
 */
union rpc_tee_param {
	struct rpc_memref memref;

	struct {
		uint32_t a;
		uint32_t b;
	} value;
};

/*
 * REE->TEE parameters for RPC session operations
 * (MBEDTEE_RPC_OPEN_SESSION / MBEDTEE_RPC_INVOKE_SESSION / MBEDTEE_RPC_CLOSE_SESSION).
 */
struct rpc_param {
	int32_t  session_id;
	uint32_t cmd_id;
	uint32_t ret_origin;
	uint32_t params_type;
	union rpc_tee_param params[4];
	uint8_t  uuid[16];
	uint8_t  clnt_uuid[16];
};

/*
 * REE->TEE cancellation request (MBEDTEE_RPC_CANCEL).
 */
struct rpc_cancel_req {
	uint32_t session_id;
	uint32_t cancel_id;
};

/*
 * TEE<->REE RPC ring buffer header (24 bytes fixed).
 */
struct rpc_ringbuf {
	uint32_t wr;              /* producer write pointer */
	uint32_t rd;              /* consumer read pointer */
	uint32_t callee_ready;    /* callee ready flag */
	uint32_t callee_imsic_id; /* RISC-V only: IMSIC local interrupt id */
	uint32_t callee_hartid;   /* RISC-V only: target hart-id for T2R notification */
	uint32_t reserved;        /* padding, must be zero */
	uint8_t  mem[];
};

/*
 * Compile-time ABI layout assertions.
 * These must match the static_assert() checks in the Linux mbedtee_msg.h.
 */
_Static_assert(sizeof(struct rpc_cmd) == 32,
	"rpc_cmd wire size mismatch");
_Static_assert(__builtin_offsetof(struct rpc_cmd, ret) == 8,
	"rpc_cmd.ret offset mismatch");
_Static_assert(__builtin_offsetof(struct rpc_cmd, waiter_id) == 16,
	"rpc_cmd.waiter_id offset mismatch");
_Static_assert(__builtin_offsetof(struct rpc_cmd, shm) == 24,
	"rpc_cmd.shm offset mismatch");
_Static_assert(__builtin_offsetof(struct rpc_cmd, data) == 32,
	"rpc_cmd.data offset mismatch");
_Static_assert(sizeof(struct rpc_memref) == 40,
	"rpc_memref wire size mismatch");
_Static_assert(sizeof(struct rpc_ringbuf) == 24,
	"rpc_ringbuf header size mismatch");
_Static_assert(sizeof(struct rpc_param) == 208,
	"rpc_param wire size mismatch");
_Static_assert(sizeof(struct rpc_cancel_req) == 8,
	"rpc_cancel_req wire size mismatch");

#ifdef __cplusplus
}
#endif

#endif
