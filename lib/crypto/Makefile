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

crypto: random.o af.o fastpbkdf2.o

cuda_crypto: random.o af.o fastpbkdf2.o cuda_pbkdf2.o

random.o: random.c
	$(COMP) -c random.c -o $(DIR)$@ 

af.o: af.c  
	$(COMP) -o $(DIR)$@ -c af.c $(DLO)

fastpbkdf2.o: fastpbkdf2.c
	$(COMP) -o $(DIR)$@ -c fastpbkdf2.c

cuda_pbkdf2_hmac_sha1.o: 
	$(NVCC) $(CUOPT) -o $(DIR)$@ -c cuda_pbkdf2_hmac_sha1.cu 

cuda_pbkdf2_hmac_sha512.o: 
	$(NVCC) $(CUOPT) -o $(DIR)$@ -c cuda_pbkdf2_hmac_sha512.cu 

cuda_pbkdf2.o: cuda_pbkdf2_hmac_sha1.o cuda_pbkdf2_hmac_sha512.o
	ld -r $(DIR)cuda_pbkdf2_hmac_sha1.o $(DIR)cuda_pbkdf2_hmac_sha512.o -o $(DIR)$@

clean:
	rm -f $(DIR)random.o $(DIR)af.o $(DIR)fastpbkdf2.o $(DIR)cuda_pbkdf2.o
