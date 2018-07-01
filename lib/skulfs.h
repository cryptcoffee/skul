/*
 *    This file is part of Skul.
 *
 *    Copyright 2016, Simone Bossi    <pyno@crypt.coffee>
 *                    Hany Ragab      <_hanyOne@crypt.coffee>
 *                    Alexandro Calo' <ax@crypt.coffee>
 *    Copyright (C) 2014 Cryptcoffee. All rights reserved.
 *
 *    Skull is a PoC to bruteforce the Cryptsetup implementation of
 *    Linux Unified Key Setup (LUKS).
 *
 *    Skul is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License version 2
 *    as published by the Free Software Foundation.
 *
 *    Skul is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with Skul.  If not, see <http://www.gnu.org/licenses/>.
 */



#ifndef SKULFS_H
#define SKULFS_H

#include <sys/types.h>
#include <stdint.h>

#define LUKS_DIGESTSIZE 20
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8
#define LUKS_KEY_DISABLED 0x0000DEAD
#define LUKS_KEY_ENABLED 0x00AC71F3
#define LUKS_STRIPES 4000
#define SECTOR_SIZE 512

typedef struct key{
	unsigned char *key;
	size_t keylen;
}lkey_t;

typedef struct key_slot{
	uint32_t active;
	uint32_t iterations;
	unsigned char *salt;
	uint32_t key_material_offset;
	uint32_t stripes;
	lkey_t   encrypted;
}keyslot_t;

typedef struct luks_header{
	unsigned char *magic;
	uint16_t version;
	unsigned char *cipher_name;
	unsigned char *cipher_mode;
	unsigned char *hash_spec;
	uint32_t payload_offset;
	uint32_t key_bytes;
	unsigned char *mk_digest;
	unsigned char *mk_digest_salt;
	uint32_t mk_digest_iter;
	unsigned char *uuid;
	keyslot_t keyslot[LUKS_NUMKEYS];
}pheader;

int read_header(pheader *header, char *path, int *slot);
int read_disk(unsigned char *disk, size_t size, char *path, size_t offset);
void print_header(pheader *header);
void print_keyslot(pheader *header,int slot);
int initfs(pheader *header, int *iv_mode, int *chain_mode, char *crypt_disk, 
		char *path, int *slot);

#endif
