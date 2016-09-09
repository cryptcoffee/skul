#ifndef _LUKS_H_
#define _LUKS_H_

#include "../src/skul.h"

typedef struct luks_ctx{

	int iv_mode;
	int chain_mode;
	int pbk_hash;
	int slot[8];
	int slot_order[8];
	int slot_number;
	int cur_slot;
	unsigned char *crypt_disk;
	lkey_t encrypted;
	pheader header;

}LUKS_CTX;


#endif
