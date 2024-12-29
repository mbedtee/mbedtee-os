# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

core-ipc-cflags-y +=

core-ipc-$(CONFIG_IPC_SHM) += shm.o
core-ipc-$(CONFIG_IPC_MSGQ) += msgq.o
