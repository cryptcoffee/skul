# debugging option for valgrind and gccf
DBG = -g -Xlinker -Map=output.map

# Compiling macros
CC = gcc 
#OPT = -Wall -pedantic -ansi -Wno-pointer-sign -D _DEFAULT_SOURCE -D_XOPEN_SOURCE=700 -D_REENTRANT -DPURIFY -O3 _BSD_SOURCE 
OPT = -Wall -pedantic -std=c99 -Wno-pointer-sign -O3 
COMP = $(CC) $(OPT)
COMPDBG = $(COMP) $(DBG)

# working directories
DIR = /tmp/skul/
LIB = lib/
BIN = bin/
SRC = src/

# openssl path
#OPENSSLI="./lib/openssl/include"	# path to include dir
#OPENSSLL="./lib/openssl/lib"		# path to lib dir

# dynamics linking options
#DLO = -ldl -lm -I${OPENSSLI} -L${OPENSSLL} -lcrypto -lssl -lpthread  -pthread 
DLO = -ldl -lm -lssl -lcrypto -lpthread -pthread

OBJS= alloclib.o skulfs.o utils.o decrypt.o random.o af.o config.o thread.o attacks.o fastpbkdf2.o 

skul: $(SRC)skul.c $(OBJS)
	$(COMP) -o $@ $(SRC)skul.c $(DIR)alloclib.o $(DIR)skulfs.o $(DIR)random.o $(DIR)af.o $(DIR)utils.o $(DIR)decrypt.o $(DIR)config.o $(DIR)thread.o $(DIR)attacks.o $(DIR)fastpbkdf2.o $(DLO) 

skul_dbg: $(SRC)skul.c $(OBJS)
	$(COMPDBG) -o $@ $(SRC)skul.c $(DIR)alloclib.o $(DIR)skulfs.o $(DIR)random.o $(DIR)af.o $(DIR)utils.o $(DIR)decrypt.o $(DIR)config.o $(DIR)thread.o $(DIR)attacks.o $(DIR)fastpbkdf2.o $(DLO) 

alloclib.o: $(LIB)alloclib.c
	$(COMP) -o $(DIR)$@ -c $(LIB)alloclib.c

skulfs.o: $(LIB)skulfs.c
	$(COMP) -o $(DIR)$@ -c $(LIB)skulfs.c

utils.o: $(LIB)utils.c
	$(COMP) -o $(DIR)$@ -c $(LIB)utils.c

decrypt.o: $(LIB)decrypt.c 
	$(COMP) -o $(DIR)$@ -c $(LIB)decrypt.c $(DLO)

random.o: $(LIB)random.c
	$(COMP) -c $(LIB)random.c -o $(DIR)$@ 

af.o: $(LIB)af.c  
	$(COMP) -o $(DIR)$@ -c $(LIB)af.c $(DLO)

config.o: $(LIB)config.c
	$(COMP) -o $(DIR)$@ -c $(LIB)config.c $(DLO)

thread.o: $(LIB)thread.c
	$(COMP) -o $(DIR)$@ -c $(LIB)thread.c $(DLO)

fastpbkdf2.o: $(LIB)fastpbkdf2.c
	$(COMP) -o $(DIR)$@ -c $(LIB)fastpbkdf2.c

attacks.o: $(LIB)attacks.c
	$(COMP) -lm -o $(DIR)$@ -c $(LIB)attacks.c

clean:
	rm $(DIR)*.o
	rm skul
	rm test
	rm test_multi

cleanlog:
	rm *.log
	rm py/*.log
