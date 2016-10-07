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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
/*#include <endian.h>*/
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/aes.h"
#include "../utils.h"
#include "_luks_decrypt.h"
#include "../crypto/af.h"
#include "../crypto/fastpbkdf2.h"
#include "luks_decrypt.h"


int check_mode(LUKS_CTX *ctx, unsigned char *cipher_mode, int *iv_mode, int *chain_mode){

	unsigned char *iv;

	*iv_mode = 0;
	*chain_mode = 0;

	/* if no '-' then ecb is used */
	if((iv = strstr(cipher_mode, "-"))==NULL){
		*iv_mode = ECB;
		ctx->gen_iv = gen_plainiv;
	}else{
	
		iv++;
		/* plain64 mode */
		if(strcmp(iv,"plain64") == 0){
			*iv_mode = PLAIN64;
			ctx->gen_iv = gen_xtsiv;
		}

		/* plain mode */
		if(strcmp(iv,"plain")==0){
			*iv_mode = PLAIN;
			ctx->gen_iv = gen_plainiv;
		}
	
		/* ESSIV mode */
		if(strcmp(iv,"essiv:sha256") == 0 ){
			*iv_mode = ESSIV;
			ctx->gen_iv = gen_essiv;
		}

		if(*iv_mode==0){
			errprint("iv generation mode not still supported\n");
			return 0;
		}

	}
	if(strncmp(cipher_mode,"ecb", 3)==0){
		*chain_mode = ECB;
		ctx->decrypt = decrypt_ECB;
		return 1;
	}

	if(strncmp(cipher_mode,"cbc", 3)==0){
		*chain_mode = CBC;
		ctx->decrypt = decrypt_CBC;
		return 1;
	}

	if(strncmp(cipher_mode,"xts", 3)==0){
		*chain_mode = XTS;
		ctx->decrypt = decrypt_XTS;
		return 1;
	}
	return 0;
}

int luks_open_key(char *key, int keylen, SKUL_CTX *ctx){ 
		
	unsigned char buff[AES_BLOCK_SIZE], iv[2*AES_BLOCK_SIZE], 
				  iv_salt[SHA256_DIGEST_LENGTH];
	unsigned int AFSectors;
	uint32_t sec, sector;
	int j=0,r=0;
	lkey_t master, split, usrKey, usrKeyhashed;
	pheader *header;

	header = &(ctx->tctx.luks->header);

	master.key = calloc(header->key_bytes+1, sizeof(char));
	master.keylen = header->key_bytes;
	split.key = calloc(ctx->tctx.luks->encrypted.keylen, sizeof(char));
	split.keylen = ctx->tctx.luks->encrypted.keylen;
	usrKey.key = key;
	usrKey.keylen = keylen;

	/* 1) hash the password provided by user */	
	usrKeyhashed.key = calloc(header->key_bytes,sizeof(char));
	usrKeyhashed.keylen = header->key_bytes;

	ctx->tctx.luks->pbkdf2_function(usrKey.key, usrKey.keylen, 
					header->keyslot[ctx->cur_pwd].salt, LUKS_SALTSIZE, 
					header->keyslot[ctx->cur_pwd].iterations,
					usrKeyhashed.key, usrKeyhashed.keylen);

	/* 2) generate iv_salt if needed for key decryption */
	if(ctx->tctx.luks->iv_mode == ESSIV){
		if(!(set_essivkey(iv_salt, usrKeyhashed.key, 32))){
			errprint("Error generating iv_salt\n");
			r=0;
			goto end;
		}
	}

	AFSectors = (int)(ceil((float)(ctx->tctx.luks->encrypted.keylen) / SECTOR_SIZE));
	memset(iv,0,2*AES_BLOCK_SIZE);

	/* iv generation for each sector */
	for(sector=0; sector<AFSectors; sector++){
		memset(buff,0,AES_BLOCK_SIZE);
		sec = htobe32(sector);

		buff[0] = (sec >> 24) & 0xff;
		buff[1] = (sec >> 16) & 0xff;
		buff[2] = (sec >> 8) & 0xff;
		buff[3] = (sec ) & 0xff;

		if(!ctx->tctx.luks->gen_iv(iv_salt, iv, &j, buff, AES_BLOCK_SIZE)){
			errprint("Error generating iv\n");
			r=0;
			goto end;
		}

		/* 3) sector by sector decryption of masterkey */	
		if(!ctx->tctx.luks->decrypt(usrKeyhashed.key,
					ctx->tctx.luks->encrypted.key+(sector*SECTOR_SIZE),
					SECTOR_SIZE, split.key+(sector*SECTOR_SIZE),iv)){
			errprint("Error decrypting masterkey\n");
			r=0;
			goto end;
		}

	}

	/* 4) Merge the decrypted masterKey */
	if(AF_merge(split.key,
					master.key,header->key_bytes,
					header->keyslot[ctx->cur_pwd].stripes, header->hash_spec)!=0){
		warn_print("[WARNING] error merging decrypted masterKey\n");
		r=0;
		goto end;
	}

	/* 5) Test master key */
	if(ctx->fast){
		r=testkeydecryption(ctx->tctx.luks, master.key, ctx->tctx.luks->crypt_disk, 
				header->key_bytes);
	}else{
		r=testkeyhash(ctx->tctx.luks, master.key, master.keylen, header->mk_digest_salt,
				header->mk_digest_iter, header->mk_digest,header->hash_spec, 
				ctx->tctx.luks->pbk_hash);
	}

end:
	/* clean the room */
	free(usrKeyhashed.key);
	free(master.key);
	free(split.key);

	return r;
}
