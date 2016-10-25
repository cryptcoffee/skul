# debugging option for valgrind and gcc
DBG = -g -Xlinker -Map=output.map

# Compiling macros
CC = gcc 
NVCC = nvcc
#OPT = -Wall -pedantic -ansi -Wno-pointer-sign -D _DEFAULT_SOURCE -D_XOPEN_SOURCE=700 -D_REENTRANT -DPURIFY -O3 _BSD_SOURCE 
OPT = -O3 -Wall -pedantic -std=c99 -Wno-pointer-sign -O3
COMP = $(CC) $(OPT) 

# working directories
DIR = /tmp/skul/
LIB = lib/
BIN = bin/
SRC = src/
CRY = lib/crypto/
LUK = lib/luks/

# openssl path
#OPENSSLI="./lib/openssl/include"	# path to include dir
#OPENSSLL="./lib/openssl/lib"		# path to lib dir

# dynamics linking options
#DLO = -ldl -lm -I${OPENSSLI} -L${OPENSSLL} -lcrypto -lssl -lpthread  -pthread 
DLO = -ldl -lm -lssl -lcrypto -lpthread -pthread
CUOPT = --compiler-options='-DCUDA_ENGINE=1 $(OPT) $(DLO)'

