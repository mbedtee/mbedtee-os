# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

drivers-rng-$(CONFIG_RNG) += rng.o
drivers-rng-$(CONFIG_PRNG) += prng.o
