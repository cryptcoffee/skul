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

-include ../../conf.mk

all: luks_cpu luks_w_cuda

luks_cpu: luks_decrypt.o _luks_decrypt.o luks.o

luks_w_cuda: luks_cuda_decrypt.o luks_cuda.o _luks_decrypt.o luks_decrypt.o 

luks_decrypt.o: luks_decrypt.c 
	$(COMP) -o $(DIR)$@ -c luks_decrypt.c $(DLO)

_luks_decrypt.o: _luks_decrypt.c
	$(COMP) -o $(DIR)$@ -c _luks_decrypt.c $(DLO)

luks.o: luks.c
	$(COMP) -o $(DIR)$@ -c luks.c

luks_cuda.o: luks.c  
	$(NVCC) -o $(DIR)$@ -c luks.c $(CUOPT)

luks_cuda_decrypt.o: luks_cuda_decrypt.c
	$(NVCC) -o $(DIR)$@ -c luks_cuda_decrypt.c $(CUOPT)


