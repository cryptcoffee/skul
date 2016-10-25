#    This file is part of Skul.
#
#    Copyright 2016, Simone Bossi    <pyno@crypt.coffee>
#                    Hany Ragab      <_hanyOne@crypt.coffee>
#                    Alexandro Calo' <ax@crypt.coffee>
#    Copyright (C) 2014 Cryptcoffee. All rights reserved.
#
#    Skull is a PoC to bruteforce the Cryptsetup implementation of
#    Linux Unified Key Setup (LUKS).
#
#    Skul is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2
#    as published by the Free Software Foundation.
#
#    Skul is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Skul.  If not, see <http://www.gnu.org/licenses/>.

-include ../conf.mk

cpu:  utils.o config.o thread.o attacks.o engine.o
cuda: utils.o config.o thread_cuda.o attacks_cuda.o engine_cuda.o

utils.o: utils.c
	$(COMP) -o $(DIR)$@ -c utils.c

config.o: config.c
	$(COMP) -o $(DIR)$@ -c config.c $(DLO)

thread.o: thread.c
	$(COMP) -o $(DIR)$@ -c thread.c $(DLO)

thread_cuda.o: thread.c
	$(COMP) -o $(DIR)$@ -c thread.c $(DLO) -DCUDA_ENGINE=1

attacks.o: attacks.c
	$(COMP) -lm -o $(DIR)$@ -c attacks.c

attacks_cuda.o: attacks.c
	$(COMP) -lm -o $(DIR)$@ -c attacks.c -DCUDA_ENGINE=1

engine.o: engine.c
	$(COMP) -o $(DIR)$@ -c engine.c

engine_cuda.o: engine.c
	$(COMP) -o $(DIR)$@ -c engine.c -DCUDA_ENGINE=1

