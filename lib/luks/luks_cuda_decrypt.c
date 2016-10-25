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



#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include "../utils.h"
#include "../config.h"
#include "luks.h"
#include "_luks_decrypt.h"
#include "../../src/skul.h"
#include "../crypto/af.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <sys/time.h>

int luks_cuda_open_key(unsigned char **keys, int numkeys, SKUL_CTX *ctx, 
		int *win_pos, int *progress){ 
		
	unsigned char buff[AES_BLOCK_SIZE], iv[2*AES_BLOCK_SIZE], 
				  iv_salt[SHA256_DIGEST_LENGTH], **master_list=NULL;
	unsigned int AFSectors;
	uint32_t sec, sector;
	int j=0,r=0,i=0;
	lkey_t master, split;
	uint8_t **usrKeyshashed;
	pheader *header;
/*	struct timeval t0,t1;
	unsigned long seconds;*/

	header = &(ctx->tctx.luks->header);

	split.key = calloc(ctx->tctx.luks->encrypted.keylen, sizeof(char));
	split.keylen = ctx->tctx.luks->encrypted.keylen;
	master.key = calloc(header->key_bytes+1, sizeof(char));
	master.keylen = header->key_bytes;

	if(!ctx->fast){
		master_list = calloc(numkeys, sizeof(char *));
		for(i=0;i<numkeys;i++)
			master_list[i] = (unsigned char *)calloc(header->key_bytes, sizeof(char));
	}

	usrKeyshashed = calloc(numkeys,sizeof(char*));
	for(i=0;i<numkeys;i++){
		usrKeyshashed[i] = calloc( LUKS_SALTSIZE, sizeof(char));
	}

	if(!(ctx->tctx.luks->cuda_pbkdf2_function(keys, numkeys, header->keyslot[ctx->cur_pwd].salt,
						LUKS_SALTSIZE, header->keyslot[ctx->cur_pwd].iterations,
						usrKeyshashed))){
//	if(!(ctx->tctx.luks->cuda_pbkdf2_function(keys, numkeys, header->keyslot[ctx->cur_pwd].salt,
//						LUKS_SALTSIZE, 64000,
//						usrKeyshashed))){

		errprint("Error hashing user keys\n");
		return 0;
	}
	
	for(i=0; i<numkeys; i++){

		if(ctx->tctx.luks->iv_mode == ESSIV){
			if(!(set_essivkey(iv_salt, usrKeyshashed[i], 32))){
				errprint("Error generating iv_salt\n");
				continue;
			}
		}

		AFSectors = (int)(ceil((float)(ctx->tctx.luks->encrypted.keylen) / SECTOR_SIZE));
		memset(iv,0,2*AES_BLOCK_SIZE);
	
		for(sector=0; sector<AFSectors; sector++){
			memset(buff,0,AES_BLOCK_SIZE);
			sec = htobe32(sector);

			buff[0] = (sec >> 24) & 0xff;
			buff[1] = (sec >> 16) & 0xff;
			buff[2] = (sec >> 8) & 0xff;
			buff[3] = (sec ) & 0xff;

			if(!ctx->tctx.luks->gen_iv(iv_salt, iv, &j, buff, AES_BLOCK_SIZE)){
				errprint("Error generating iv\n");
				continue;
			}
	
			if(!ctx->tctx.luks->decrypt(usrKeyshashed[i],
						ctx->tctx.luks->encrypted.key+(sector*SECTOR_SIZE),
						SECTOR_SIZE, split.key+(sector*SECTOR_SIZE),iv)){
				errprint("Error decrypting masterkey\n");
				continue;
			}
		}

		if(AF_merge(split.key,
					master.key,header->key_bytes,
					header->keyslot[ctx->cur_pwd].stripes, header->hash_spec)!=0){
			errprint("error merging decrypted masterKey\n");
			continue;
		}
	
		if(ctx->fast){
			r=testkeydecryption(ctx->tctx.luks, master.key, ctx->tctx.luks->crypt_disk, 
					header->key_bytes);
//			r=testkeydecryption(ctx->tctx.luks, usrKeyshashed[i], ctx->tctx.luks->crypt_disk, 
//					header->key_bytes);


			if(r){
				*win_pos = i;
				r=1;
				goto end;
			}

			*progress = *progress +1;
		}else{
			memcpy(master_list[i], master.key, header->key_bytes);
		}

	}
	
	if(!ctx->fast){
		r=cuda_testkeyhash(ctx->tctx.luks, master_list, numkeys, header->mk_digest_salt,
				header->mk_digest_iter, header->mk_digest, win_pos, progress);
	}

end:
	/* clean the room */
	free(master.key);
	free(split.key);
	for(i=0;i<numkeys;i++){
		free(usrKeyshashed[i]);
	}
	free(usrKeyshashed);
	if(!ctx->fast){
		for(i=0;i<numkeys;i++)
			free(master_list[i]);
		free(master_list);
	}

	return r;

}