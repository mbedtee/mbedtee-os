# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>

MAJOR_VER = 1
MEDIUM_VER = 0
MINOR_VER = 1

export PRODUCT = mbedtee

export TOP_DIR = $(CURDIR)

export CONFIG_FILE = $(TOP_DIR)/.config
export SCRIPTS_DIR = $(TOP_DIR)/scripts
export PRODUCT_VERSION = $(MAJOR_VER).$(MEDIUM_VER).$(MINOR_VER)

VERSION_FILE=$(TOP_DIR)/include/version.h
BUILD_FILE=$(TOP_DIR)/include/build.h

include $(SCRIPTS_DIR)/Makefile.include

# Any Kconfig change should trigger regeneration of auto.conf/autoconf.h,
KCONFIG_FILES := $(shell find $(TOP_DIR) -name Kconfig -o -name Kconfig.host)

.PHONY: all
all: $(VERSION_FILE) $(BUILD_FILE) stage-kern

# ====================================================
# Dependency-based build stages for parallel make
#
# Dependency graph:
#   dt --------------------------------------|
#   kern-scripts -> kern-compile ------------|
#   ramfs -> ramfs_asm ----------------------|
#   ramfs -> libc -> app --------------------|
#                                            |-> kern
# ====================================================

# --- Stage: ramfs image creation (independent) ---
.PHONY: stage-ramfs
stage-ramfs: | $(OUTPUT_DIR)
ifeq ($(CONFIG_RAMFS),y)
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.ramfs all
endif

# --- Stage: ramfs assembly (depends on ramfs image) ---
.PHONY: stage-ramfs-asm
stage-ramfs-asm: stage-ramfs
ifeq ($(CONFIG_RAMFS),y)
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.ramfs ramfs_asm
endif

# --- Stage: libc (depends on ramfs image for fatcopy) ---
.PHONY: stage-libc
stage-libc: stage-ramfs
ifeq ($(CONFIG_USER),y)
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.libc all
endif

# --- Stage: apps (depends on libc) ---
.PHONY: stage-app
stage-app: stage-libc
ifeq ($(CONFIG_USER),y)
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.app all
endif

# --- Stage: kernel scripts (independent) ---
.PHONY: stage-kern-scripts
stage-kern-scripts: | $(OUTPUT_DIR)
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.kern scripts

# --- Stage: device tree (generates dtb.S needed by kern-compile) ---
.PHONY: stage-dt
stage-dt: | $(OUTPUT_DIR)
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.dt all

# --- Stage: kernel objects compilation (depends on dt for generated dtb.S) ---
.PHONY: stage-kern-compile
stage-kern-compile: stage-kern-scripts stage-dt | $(OUTPUT_DIR)
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.kern objs

# --- Stage: kernel final link (depends on all above) ---
.PHONY: stage-kern
stage-kern: stage-kern-compile stage-ramfs-asm stage-app stage-dt
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.kern all

$(OUTPUT_DIR):
	$(Q)mkdir -p $(OUTPUT_DIR)

.PHONY: clean
clean:
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.ramfs clean
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.libc clean
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.app clean
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.dt clean
	$(Q)$(MAKE) -C $(SCRIPTS_DIR) -f Makefile.kern clean
	$(Q)rm -rf $(OUTPUT_DIR)
	$(Q)rm -f $(VERSION_FILE) $(BUILD_FILE)
	$(Q)rm -f .stamp_built

.PHONY: $(BUILD_FILE)
$(BUILD_FILE):
	@( printf '#ifndef _BUILD_H\n' ) > $@.tmp
	@( printf '#define _BUILD_H\n' ) >> $@.tmp
	@( printf '#define BUILD_TIME_SEC "%s"\n' `date +%s`) >> $@.tmp
	@( printf '#define BUILD_TIME_NSEC "%s"\n' `date +%N`) >> $@.tmp
	@( printf '#define BUILD_TIME_ZONE "%s"\n' `date +%z`) >> $@.tmp
	@( printf '#define BUILD_TAG "%s"\n' "$(BUILD_VERSION)") >> $@.tmp
	@( printf '#endif\n' ) >> $@.tmp
	@cmp -s $@ $@.tmp && rm -f $@.tmp || mv -f $@.tmp $@

.PHONY: $(VERSION_FILE)
$(VERSION_FILE):
	@( printf '#ifndef _VERSION_H\n' ) > $@.tmp
	@( printf '#define _VERSION_H\n' ) >> $@.tmp
	@( printf '#define PRODUCT_NAME "%s"\n' '$(PRODUCT)') >> $@.tmp
	@( printf '#define PLATFORM_NAME "%s"\n' '$(PLATFORM)') >> $@.tmp
	@( printf '#define PRODUCT_VERSION "%s"\n' '$(PRODUCT_VERSION)') >> $@.tmp
	@( echo "#define PRODUCT_VERSION_INT ($(MAJOR_VER)<<16 |"\
		"$(MEDIUM_VER)<<8 | $(MINOR_VER))") >> $@.tmp
	@( printf '#define TOOLCHAIN_TARGET "%s"\n' "`$(cc) -dumpmachine`") >> $@.tmp
	@( printf '#define TOOLCHAIN_FORMAT "%s"\n' "`$(ld) -EL --print-output-format`") >> $@.tmp
	@( printf '#endif\n' ) >> $@.tmp
	@cmp -s $@ $@.tmp && rm -f $@.tmp || mv -f $@.tmp $@

menuconfig:
	$(Q)$(SCRIPTS_DIR)/kconfig/menuconfig.py

savedefconfig:
	$(Q)$(SCRIPTS_DIR)/kconfig/savedefconfig_full.py

%defconfig:
	$(Q)$(SCRIPTS_DIR)/kconfig/defconfig.py configs/$@ 2>&1 > /dev/null

# Detect if the .config is newer than auto.conf, update autoconf.h accordingly
-include $(INC_DIR)/config/auto.conf
$(INC_DIR)/config/auto.conf: $(CONFIG_FILE) $(KCONFIG_FILES)
	$(Q)mkdir -p $(INC_DIR)/generated $(INC_DIR)/config
	$(Q)$(SCRIPTS_DIR)/kconfig/genconfig.py \
		--sync-deps=$(INC_DIR)/config --header-path=$(INC_DIR)/generated/autoconf.h
