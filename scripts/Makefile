# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

include $(SCRIPTS_DIR)/Makefile.include

.PHONY: all
all:
ifeq ($(CONFIG_RAMFS),y)
	$(Q)$(MAKE) -f Makefile.ramfs all
endif
ifeq ($(CONFIG_USER),y)
	$(Q)$(MAKE) -f Makefile.libc all
	$(Q)$(MAKE) -f Makefile.app all
endif

	$(Q)$(MAKE) -f Makefile.kern scripts
	$(Q)$(MAKE) -f Makefile.dt all
	$(Q)$(MAKE) -f Makefile.kern all

.PHONY: clean
clean:
	$(Q)$(MAKE) -f Makefile.ramfs clean
	$(Q)$(MAKE) -f Makefile.libc clean
	$(Q)$(MAKE) -f Makefile.app clean
	$(Q)$(MAKE) -f Makefile.dt clean
	$(Q)$(MAKE) -f Makefile.kern clean
