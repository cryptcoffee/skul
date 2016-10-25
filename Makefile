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


# debugging option for valgrind and gcc
DBG = -g -Xlinker -Map=output.map

# Compiling macros
CC = gcc 
NVCC = nvcc
#OPT = -Wall -pedantic -ansi -Wno-pointer-sign -D _DEFAULT_SOURCE -D_XOPEN_SOURCE=700 -D_REENTRANT -DPURIFY -O3 _BSD_SOURCE 
#OPT = -O3 #-Wall -pedantic -std=c99 -Wno-pointer-sign -O3
COMP = $(CC) $(OPT) 

# working directories
DIR = /tmp/skul/
LIB = lib/
BIN = bin/
SRC = src/
CRY = lib/crypto/
LUK = lib/luks/

-include lib/luks/luks.mk

# openssl path
#OPENSSLI="./lib/openssl/include"	# path to include dir
#OPENSSLL="./lib/openssl/lib"		# path to lib dir

# dynamics linking options
#DLO = -ldl -lm -I${OPENSSLI} -L${OPENSSLL} -lcrypto -lssl -lpthread  -pthread 
DLO = -ldl -lm -lssl -lcrypto -lpthread -pthread
CUOPT = --compiler-options='-DCUDA_ENGINE=1 $(OPT) $(DLO)'

OBJS= random.o af.o config.o fastpbkdf2.o luks.o utils.o luks_decrypt.o thread.o attacks.o engine.o _luks_decrypt.o
CUOBJS= random.o af.o config.o fastpbkdf2.o luks_cuda.o utils.o luks_cuda_decrypt.o luks_decrypt.o _luks_decrypt.o thread_cuda.o attacks_cuda.o engine_cuda.o cuda_pbkdf2.o luks_cuda.o

skul: $(SRC)skul.c $(OBJS)
	$(COMP) -o $@ $(SRC)skul.c $(DIR)luks.o $(DIR)random.o $(DIR)af.o $(DIR)utils.o $(DIR)luks_decrypt.o $(DIR)config.o $(DIR)thread.o $(DIR)attacks.o $(DIR)fastpbkdf2.o $(DIR)engine.o $(DIR)_luks_decrypt.o $(DLO)

skulcu: $(SRC)skul.c $(CUOBJS)
	$(NVCC) -o $@ $(SRC)skul.c $(DIR)luks_cuda.o $(DIR)random.o $(DIR)af.o $(DIR)utils.o $(DIR)luks_decrypt.o $(DIR)config.o $(DIR)thread_cuda.o $(DIR)attacks_cuda.o $(DIR)fastpbkdf2.o $(DIR)engine_cuda.o $(DIR)cuda_pbkdf2.o $(DIR)luks_cuda_decrypt.o $(DIR)_luks_decrypt.o $(CUOPT)

skul_dbg: $(SRC)skul.c $(OBJS)
	$(COMPDBG) -o $@ $(SRC)skul.c $(DIR)random.o $(DIR)af.o $(DIR)utils.o $(DIR)luks_decrypt.o $(DIR)config.o $(DIR)thread.o $(DIR)attacks.o $(DIR)fastpbkdf2.o $(DLO) 

utils.o: $(LIB)utils.c
	$(COMP) -o $(DIR)$@ -c $(LIB)utils.c

luks_decrypt.o: $(LUK)luks_decrypt.c 
	$(COMP) -o $(DIR)$@ -c $(LUK)luks_decrypt.c $(DLO)

_luks_decrypt.o: $(LUK)_luks_decrypt.c
	$(COMP) -o $(DIR)$@ -c $(LUK)_luks_decrypt.c $(DLO)

random.o: $(CRY)random.c
	$(COMP) -c $(CRY)random.c -o $(DIR)$@ 

af.o: $(CRY)af.c  
	$(COMP) -o $(DIR)$@ -c $(CRY)af.c $(DLO)

config.o: $(LIB)config.c
	$(COMP) -o $(DIR)$@ -c $(LIB)config.c $(DLO)

thread.o: $(LIB)thread.c
	$(COMP) -o $(DIR)$@ -c $(LIB)thread.c $(DLO)

thread_cuda.o: $(LIB)thread.c
	$(COMP) -o $(DIR)$@ -c $(LIB)thread.c $(DLO) -DCUDA_ENGINE=1

fastpbkdf2.o: $(CRY)fastpbkdf2.c
	$(COMP) -o $(DIR)$@ -c $(CRY)fastpbkdf2.c

attacks.o: $(LIB)attacks.c
	$(COMP) -lm -o $(DIR)$@ -c $(LIB)attacks.c

attacks_cuda.o: $(LIB)attacks.c
	$(COMP) -lm -o $(DIR)$@ -c $(LIB)attacks.c -DCUDA_ENGINE=1

luks.o: $(LUK)luks.c
	$(COMP) -o $(DIR)$@ -c $(LUK)luks.c

luks_cuda.o: $(LUK)luks.c
	$(COMP) -o $(DIR)$@ -c $(LUK)luks.c -DCUDA_ENGINE=1

engine.o: $(LIB)engine.c
	$(COMP) -o $(DIR)$@ -c $(LIB)engine.c

engine_cuda.o: $(LIB)engine.c
	$(COMP) -o $(DIR)$@ -c $(LIB)engine.c -DCUDA_ENGINE=1

luks_cuda_decrypt.o: $(LUK)luks_cuda_decrypt.c
	$(COMP) -o $(DIR)$@ -c $(LUK)luks_cuda_decrypt.c

cuda_pbkdf2.o: $(CRY)cuda_pbkdf2.cu 
	$(NVCC) $(CUOPT) -o $(DIR)$@ -c $(CRY)cuda_pbkdf2.cu 


clean:
	rm $(DIR)*.o
	rm skul
	rm test
	rm test_multi

cleanlog:
	rm *.log
	rm py/*.log
