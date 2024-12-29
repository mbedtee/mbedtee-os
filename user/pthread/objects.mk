# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

user-pthread-cflags-y +=

user-pthread-uobjs-$(CONFIG_USER_PTHREAD) += \
	entry.o pthread.o \
	pthread_attr.o pthread_attr_sched.o \
	pthread_cancel.o pthread_cleanup.o \
	pthread_key.o pthread_spinlock.o \
	pthread_rwlock.o pthread_barrier.o \
	pthread_mutex.o pthread_mutexdep.o \
	pthread_wait.o pthread_cond.o \
	pthread_object.o pthread_reent.o \
	pthread_session.o
