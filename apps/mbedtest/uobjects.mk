# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

# application name
obj-$(CONFIG_MBEDTEST) += mbedtest.elf

# application extra cflags
mbedtest-cflags += -Wstack-usage=5120

# application sub-objects
mbedtest-y += mbedtest.o
mbedtest-y += mbedtest_main.o
mbedtest-y += mbedtest_float.o
mbedtest-y += mbedtest_misc.o
mbedtest-y += mbedtest_rand.o
mbedtest-y += mbedtest_fs.o
mbedtest-y += mbedtest_io.o
mbedtest-y += mbedtest_pipe.o
mbedtest-y += mbedtest_signal.o
mbedtest-y += mbedtest_pthread.o
mbedtest-y += mbedtest_mq.o
mbedtest-y += mbedtest_sem.o
mbedtest-y += mbedtest_timer.o
mbedtest-y += mbedtest_process.o
mbedtest-$(CONFIG_MBEDTEST_CRYPTO) += mbedtest_crypto.o
