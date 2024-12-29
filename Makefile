# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

MAJOR_VER = 1
MEDIUM_VER = 0
MINOR_VER = 1

export PRODUCT = mbedtee

export TOP_DIR = $(CURDIR)

export HOSTCC  = gcc
export HOSTCXX = g++
export HOSTLD  = ld
export YACC = bison
export LEX = flex
export srctree = $(TOP_DIR)
export objtree = $(TOP_DIR)
export quiet = quiet_

export CONFIG_FILE = $(TOP_DIR)/.config
export SCRIPTS_DIR = $(TOP_DIR)/scripts

include $(SCRIPTS_DIR)/Makefile.include
include $(SCRIPTS_DIR)/menuconfig/Kbuild.include

export PRODUCT_VERSION = $(MAJOR_VER).$(MEDIUM_VER).$(MINOR_VER)

VERSION_FILE=$(TOP_DIR)/include/version.h
BUILD_FILE=$(TOP_DIR)/include/build.h

.PHONY: all
all: $(VERSION_FILE) $(BUILD_FILE)
	$(Q)mkdir -p $(OUTPUT_DIR)
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) all

.PHONY: clean
clean:
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) clean
	$(Q)rm -rf $(OUTPUT_DIR)
	$(Q)rm -f $(VERSION_FILE) $(BUILD_FILE)
	$(Q)rm -f .stamp_built

.PHONY: $(BUILD_FILE)
$(BUILD_FILE):
	@( printf '#ifndef _BUILD_H\n' ) > $@.tmp
	@( printf '#define _BUILD_H\n' ) >> $@.tmp
	@( printf '#define BUILD_TIME_SEC %s\n' "\"`date +%_s`\"") >> $@.tmp
	@( printf '#define BUILD_TIME_NSEC %s\n' "\"`date +%_N`\"") >> $@.tmp
	@( printf '#define BUILD_TAG "%s"\n' "$(BUILD_VERSION)") >> $@.tmp
	@( printf '#endif\n' ) >> $@.tmp
	@cmp -s $@ $@.tmp && rm -f $@.tmp || mv -f $@.tmp $@

.PHONY: $(VERSION_FILE)
$(VERSION_FILE):
	@( printf '#ifndef _VERSION_H\n' ) > $@.tmp
	@( printf '#define _VERSION_H\n' ) >> $@.tmp
	@( printf '#define PRODUCT_NAME "%s"\n' '$(PRODUCT)') >> $@.tmp
	@( printf '#define PRODUCT_VERSION "%s"\n' '$(PRODUCT_VERSION)') >> $@.tmp
	@( echo "#define PRODUCT_VERSION_INT ($(MAJOR_VER)<<16 |"\
		"$(MEDIUM_VER)<<8 | $(MINOR_VER))") >> $@.tmp
	@( printf '#define TOOLCHAIN_TARGET "%s"\n' "`$(cc) -dumpmachine`") >> $@.tmp
	@( printf '#define TOOLCHAIN_FORMAT "%s"\n' "`$(ld) -EL --print-output-format`") >> $@.tmp
	@( printf '#endif\n' ) >> $@.tmp
	@cmp -s $@ $@.tmp && rm -f $@.tmp || mv -f $@.tmp $@

.PHONY: $(scripts_basic)
scripts_basic:
	$(Q)$(MAKE) $(build)=scripts/menuconfig/basic

%config: scripts_basic
	$(Q)$(MAKE) $(build)=scripts/menuconfig/kconfig $@ 2> /dev/null

# Detect if the .config is newer than auto.conf, update autoconf.h accordingly
-include include/config/auto.conf.cmd
%/config/auto.conf %/config/auto.conf.cmd %/generated/autoconf.h: $(CONFIG_FILE)
	$(Q)$(MAKE) $(build)=scripts/menuconfig/kconfig syncconfig