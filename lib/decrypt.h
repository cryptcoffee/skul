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



#ifndef _DECRYPT_H_
#define _DECRYPT_H_

#include "skulfs.h"
#include <openssl/evp.h>

#define ECB 1
#define CBC 2
#define XTS 3
#define PLAIN 32
#define PLAIN64 64
#define ESSIV 256

#define SHA_ONE 1
#define SHA_TWO_FIVE_SIX 2
#define SHA_FIVE_ONE_TWO 3

int decrypt(int mode, unsigned char *key, unsigned char *encryptedData, 
		int encryptedLength,unsigned int * length, 
		unsigned char *decryptedData, unsigned char *iv);

int set_essivkey(unsigned char *ivkey, unsigned char *usrkey, int len);

int gen_essiv(unsigned char *key, unsigned char *ciphertext, 
		int *outlen, unsigned char *plaintext, 
		int length);

int check_mode(unsigned char *cipher_mode, int *iv_mode, int *chain_mode);

int testkeyhash(char *key, int keylen, char *salt, 
		int iterations, char *hash, char *hash_spec, int pbk_hash);

int testkeydecryption(int mode, char *key, char *crypt_disk, int keylen);

int open_key(char *key, int keylen, pheader *header, int iv_mode,
		int chain_mode, lkey_t *encrypted, char *crypt_disk, 
		int quick_test, int keyslot, int pbk_hash);

#endif

