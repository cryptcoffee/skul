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

-include conf.mk

skul: $(SRC)skul.c
	cd $(LIB); make cpu
	cd $(CRY); make crypto
	cd $(LUK); make luks_cpu
	$(COMP) -o $@ $(SRC)skul.c $(DIR)luks.o $(DIR)random.o $(DIR)af.o $(DIR)utils.o $(DIR)luks_decrypt.o $(DIR)config.o $(DIR)thread.o $(DIR)attacks.o $(DIR)fastpbkdf2.o $(DIR)engine.o $(DIR)_luks_decrypt.o $(DLO)

skulcu: $(SRC)skul.c
	cd $(LIB); make cuda
	cd $(CRY); make cuda_crypto
	cd $(LUK); make luks_w_cuda
	$(NVCC) -o $@ $(SRC)skul.c $(DIR)luks_cuda.o $(DIR)random.o $(DIR)af.o $(DIR)utils.o $(DIR)luks_decrypt.o $(DIR)config.o $(DIR)thread_cuda.o $(DIR)attacks_cuda.o $(DIR)fastpbkdf2.o $(DIR)engine_cuda.o $(DIR)cuda_pbkdf2.o $(DIR)luks_cuda_decrypt.o $(DIR)_luks_decrypt.o $(CUOPT)


clean:
	rm -f $(DIR)*.o
	rm -f skul
	rm -f skulcu

