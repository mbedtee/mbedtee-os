# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

include $(SCRIPTS_DIR)/Makefile.include

TA_SRC = $(TOP_DIR)/apps
TA_BUILD = $(OUTPUT_DIR)/ta

ta_cflags   = $(cflags) $(user-inc-y) $(TARGET_PICFLAGS)
ta_asflags  = $(asflags) $(user-inc-y) $(TARGET_PICFLAGS)
ta_ldflags  = -EL -nostdlib -z max-page-size=4096 -pie -o
ta_libs     = $(libgcc) -L$(BINARY_DIR) -lc

include $(shell find $(TA_SRC) -iname "uobjects.mk")

ta-dir = $(shell find $(TA_SRC) -mindepth 1 -maxdepth 1 -type d)

ta-obj = $(foreach ta,$(obj-y),$(TA_BUILD)/$(ta))

ta-config = $(foreach ta,$(obj-y),$(TA_SRC)/$(ta:.elf=)/$(ta:.elf=.config))

ta-dep = $(shell set -e;                                       \
    name=`echo $(1) | awk -F '/' '{print $$NF}'`;              \
    dir=$(2)/$(subst $(TOP_DIR)/,,$(1));                       \
    mkdir -p $$dir; dep=$(2)/$$name.dep;                       \
    objs=$$name"-objs"; objs_y=$$name"-y";                     \
    cp -f $(1)/uobjects.mk $$dep;                              \
    sed -i 's/obj-/application-/' $$dep;                       \
    echo $$objs"=\$$(foreach obj,\$$("$$objs_y")," $$dir/"\$$(obj))\n" >> $$dep; \
    echo "-include \$$("$$objs":.o=.d)\n" >> $$dep;            \
    echo $(2)/$$name".elf: \$$("$$objs")" >> $$dep;            \
    echo "	\$$(Q)\$$(ld) \$$(ta_ldflags)\$$@ \$$^ \$$(ta_libs)" >> $$dep; \
    echo "	\$$(Q)\$$(strip) -d -R .comment \$$@" >> $$dep;    \
    echo "	\$$(Q)\$$(objdump) -d \$$@ > \$$@.dis\n" >> $$dep; \
    echo "$$name-cflags += -I$(1) -I$(1)/include\n" >> $$dep;  \
    echo "$$name-asflags += -I$(1) -I$(1)/include\n" >> $$dep; \
    echo "$$dir/%.o: $(1)/%.c" >> $$dep;   \
    echo "	\$$(Q)mkdir -p \`dirname "\$$@"\`" >> $$dep;  \
    echo "	\$$(if \$$(Q), @echo \" (CC) 	   \$$(subst $(TA_BUILD)/,,\$$@)\")" >> $$dep; \
    echo "	\$$(Q)\$$(cc) \$$(ta_cflags) \$$($$name-cflags) -c \$$< -o \$$@\n" >> $$dep; \
    echo "$$dir/%.o: $(1)/%.S" >> $$dep;   \
    echo "	\$$(Q)mkdir -p \`dirname "\$$@"\`" >> $$dep;  \
    echo "	\$$(if \$$(Q), @echo \" (AS) 	   \$$(subst $(TA_BUILD)/,,\$$@)\")" >> $$dep; \
    echo "	\$$(Q)\$$(cc) \$$(ta_asflags) \$$($$name-asflags) -c \$$< -o \$$@" >> $$dep; \
	echo $$dep                       )

include $(foreach dir,$(ta-dir),$(call ta-dep,$(dir),$(TA_BUILD)))

.PHONY: all
all: $(ta-config) $(ta-obj)
	$(Q)$(foreach ta,$(ta-obj),$(call fatcopy,$(ramfs_file),$(ta),/apps/))
	$(Q)$(foreach tac,$(ta-config),$(call fatcopy,$(ramfs_file),$(tac),/apps/))

.PHONY: clean
clean:
	$(if $(Q), @echo " (RM) 	   $(subst $(TOP_DIR)/,,$(TA_BUILD))")
	$(Q)rm -rf $(TA_BUILD)
