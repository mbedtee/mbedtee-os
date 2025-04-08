# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)

include $(SCRIPTS_DIR)/Makefile.dt

DTS_SRC := platform

.PHONY: dtb
dtb: $(DTS_BUILD)/$(DTS_SRC).o $(DTS_BUILD)/$(DTS_SRC).dtb
	$(Q)touch $(DTS_BUILD)/$(DTS_SRC).dtb