#ifndef ALLOCLIB_H
#define ALLOCLIB_H

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "skulfs.h"

#define LUKS_DIGESTSIZE 20
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8
#define LUKS_KEY_DISABLED 0x0000DEAD
#define LUKS_KEY_ENABLED 0x00AC71F3
#define LUKS_STRIPES 4000

int alloc_header(pheader *header);
void freeheader(pheader *header);
char *readline(FILE *f, int *max_l);

#endif
