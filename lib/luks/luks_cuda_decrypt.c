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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "../../src/skul.h"
#include <openssl/evp.h>

int decrypt_ECB(unsigned char *key, unsigned char *encrypted, int encrypted_len,
		unsigned char * decrypted, unsigned char *iv){
	int decryptedLength, lastDecryptLength = 0;
	EVP_CIPHER_CTX cipher;

	decryptedLength = 0;
	lastDecryptLength = 0;

	EVP_CIPHER_CTX_init(&cipher);

	if(1 != EVP_DecryptInit_ex(&cipher, 
				EVP_aes_256_ecb(), NULL, key, NULL)){
		errprint("Error setting aes\n");
		return 0;
	}

	if(!EVP_CIPHER_CTX_set_padding(&cipher, 0)){
		errprint("This is so strange.. set padding should always return 1\n");
		return 0;
	}

	if(!EVP_DecryptUpdate(&cipher, 
				decryptedData, &decryptedLength, 
				encryptedData, encryptedLength)){
		errprint("EVP_DecryptUpdate_ex error\n");
		return 0;
	}

	if(!EVP_DecryptFinal_ex(&cipher, 
			decryptedData + decryptedLength, 
			&lastDecryptLength)){
		errprint("EVP_DecryptFinal_ex error\n");
		return 0;
	}
	
	*length = decryptedLength + lastDecryptLength;
	
	EVP_CIPHER_CTX_cleanup(&cipher);
	return 1;


}

int decrypt_CBC(unsigned char *key, unsigned char *encrypted, int encrypted_len,
		unsigned char * decrypted, unsigned char *iv){

	int decryptedLength, lastDecryptLength = 0;
	EVP_CIPHER_CTX cipher;

	decryptedLength = 0;
	lastDecryptLength = 0;

	EVP_CIPHER_CTX_init(&cipher);

	if(1 != EVP_DecryptInit_ex(&cipher, 
				EVP_aes_256_cbc(), NULL, key, iv)){
		errprint("Error setting aes\n");
		return 0;
	}

	if(!EVP_CIPHER_CTX_set_padding(&cipher, 0)){
		errprint("This is so strange.. set padding should always return 1\n");
		return 0;
	}

	if(!EVP_DecryptUpdate(&cipher, 
				decryptedData, &decryptedLength, 
				encryptedData, encryptedLength)){
		errprint("EVP_DecryptUpdate_ex error\n");
		return 0;
	}

	if(!EVP_DecryptFinal_ex(&cipher, 
			decryptedData + decryptedLength, 
			&lastDecryptLength)){
		errprint("EVP_DecryptFinal_ex error\n");
		return 0;
	}
	
	*length = decryptedLength + lastDecryptLength;
	
	EVP_CIPHER_CTX_cleanup(&cipher);
	return 1;

}

int decrypt_XTS(unsigned char *key, unsigned char *encrypted, int encrypted_len
		unsigned char * decrypted, unsigned char *iv){

	int decryptedLength, lastDecryptLength = 0;
	EVP_CIPHER_CTX cipher;

	decryptedLength = 0;
	lastDecryptLength = 0;

	EVP_CIPHER_CTX_init(&cipher);

	if(1 != EVP_DecryptInit_ex(&cipher, 
				EVP_aes_256_xts(), NULL, key, iv)){
		errprint("Error setting aes\n");
		return 0;
	}

	if(!EVP_CIPHER_CTX_set_padding(&cipher, 0)){
		errprint("This is so strange.. set padding should always return 1\n");
		return 0;
	}

	if(!EVP_DecryptUpdate(&cipher, 
				decryptedData, &decryptedLength, 
				encryptedData, encryptedLength)){
		errprint("EVP_DecryptUpdate_ex error\n");
		return 0;
	}

	if(!EVP_DecryptFinal_ex(&cipher, 
			decryptedData + decryptedLength, 
			&lastDecryptLength)){
		errprint("EVP_DecryptFinal_ex error\n");
		return 0;
	}
	
	*length = decryptedLength + lastDecryptLength;
	
	EVP_CIPHER_CTX_cleanup(&cipher);
	return 1;

}

int set_essivkey(unsigned char *ivkey, 
		unsigned char *usrkey, int len){

	SHA256_CTX sha256;

	if(!(SHA256_Init(&sha256))){
		errprint("SHA256_Init error!\n");
		return 0;
	}
	if(!(SHA256_Update(&sha256,
					usrkey,len))){ 
		errprint("SHA256_Update error\n");
		return 0;
	}
	if(!(SHA256_Final(ivkey,&sha256))){
		errprint("SHA256_Final error\n");
		return 0;
	}

	return 1;
}

int gen_essiv(unsigned char *key, unsigned char *ciphertext, 
		int *outlen, unsigned char *plaintext, 
		int length){

	int outl, lastDecryptLength=0, r=1;
	EVP_CIPHER_CTX cipher;

	outl = 0;
	lastDecryptLength = 0;

	/* Create and initialise the context */
	EVP_CIPHER_CTX_init(&cipher);

	/* Initialise the decryption operation. */
	if(1 != EVP_EncryptInit_ex(&cipher, EVP_aes_256_ecb(), NULL, key, NULL)){ 
		printf("Error setting aes\n");
		r=0;
		goto end;
	}

	if(!EVP_CIPHER_CTX_set_padding(&cipher, 0)){
		printf("This is so strange.. should always return 1\n");
	}

	if(!EVP_EncryptUpdate(&cipher, 
				ciphertext, &outl, 
				plaintext, length)){
		printf("EVP_DecryptUpdate_ex error\n");
		r=0;
		goto end;
	}

	if(!EVP_EncryptFinal_ex(&cipher, 
			plaintext + outl, 
			&lastDecryptLength)){
		printf("EVP_DecryptFinal_ex error\n");
		r=0;
		goto end;
	}
	
	*outlen = outl + lastDecryptLength;
	
end:

	EVP_CIPHER_CTX_cleanup(&cipher);
	return r;
}

int gen_xtsiv(unsigned char *iv_salt, unsigned char *iv, 
		int *outlen, unsigned char *buff, int length){

	// xts plain doesn't use salt
	snprintf(iv,length,"%s",buff);
	*outlen = lenght;

	return 1;

}

int gen_plainiv(unsigned char *iv_salt, unsigned char *iv, 
		int *outlen, unsigned char *buff, int length){

	// plain iv doesn't use salt
	memcpy(iv, buff, lenght);
	*outlen = length;

	return 1;
}

int testkeyhash(char **key_list, int numkeys, char *salt, 
		int iterations, char *hash, int *win_pos){

	char **keyhashes;
	int i,j,win=0;

	keyhashes = calloc(numkeys, sizeof(char *));
	for(i=0;i<numkeys;i++){
		keyhashes[i] = calloc(LUKS_DIGESTSIZE,sizeof(char));
	}

	if(!(header->pbkdf2_funcion(key_list, numkeys, salt,
						LUKS_SALTSIZE, iterations,
						keyhahses))){
		errprint("Error hashing user keys\n");
		win=0;
		goto end;
	}


	for(i=0;i<numkeys;i++){
		j=memcmp(keyhashes[i], hash, LUKS_DIGESTSIZE);
		if(j=0){ 
			*win_pos=i;
			win=1;
			break;
		}
	}

end:
	for(i=0;i<numkeys;i++){
		free(keyhashes[i]);
	}
	free(keyhashes);

	return win;
}

int testkeydecryption(int mode, char *key, char *crypt_disk, int keylen){

	char plain_disk[32],*xtsiv;
	int i,len;

	unsigned char guess[64] = {	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00	};

	ctx->decrypt(key, crypt_disk, 16, &len, plain_disk, guess); // using guess as a random iv
	i=memcmp(plain_disk, guess, 16);

	if(i!=0)
		return 0;

	return 1;
}


int luks_cuda_open_key(char **keys, int numkeys, SKUL_CTX *ctx, int *win_pos){ 
		
	unsigned char buff[AES_BLOCK_SIZE], iv[2*AES_BLOCK_SIZE], 
				  iv_salt[SHA256_DIGEST_LENGTH], *master_list;
	unsigned int AFSectors, outl;
	uint32_t sec, sector;
	int j=0,r=0;
	lkey_t master, split, usrKey;
	uint8_t userKeyshashed;
	pheader *header;


	header = &(ctx->tctx.luks->header);

	split.key = calloc(ctx->tctx.luks->encrypted.keylen, sizeof(char));
	split.keylen = ctx->tctx.luks->encrypted.keylen;
	master.key = calloc(header->key_bytes+1, sizeof(char));
	master.keylen = header->key_bytes;

	if(!ctx->fast){
		master_list = calloc(numkeys, sizeof(char *));
		for(i=0;i<numkeys;i++)
			master_list[i] = calloc(header->key_bytes, sizeof(char));
	}

	usrKeyshashed = calloc(numkeys,sizeof(char*));
	for(i=0;i<numkeys;i++){
		usrKeyshashed[i] = calloc( strlen(key[i]), sizeof(char));
	}

	if(!(header->pbkdf2_funcion(keys, numkeys, header->keyslot[ctx->cur_pwd].salt,
						LUKS_SALTSIZE, header->keyslot[ctx->cur_pwd].iterations,
						userKeyshashed))){
		errprint("Error hashing user keys\n");
		return 0;
	}
	
	for(i=0; i<numkeys; i++){

		if(ctx->tctx.luks->iv_mode == ESSIV){
			if(!(set_essivkey(iv_salt, usrKeyhashed.key, 32))){
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

			if(!header->gen_iv(iv_salt, iv, &j, buff, AES_BLOCK_SIZE)){
				errprint("Error generating iv\n");
				continue;
			}
	
			if(!header->decrypt(userKeyshashed[i],
						ctx->tctx.luks->encrypted.key+(sector*SECTOR_SIZE),
						SECTOR_SIZE,&outl, split.key+(sector*SECTOR_SIZE),iv)){
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
			r=testkeydecryption(master.key, ctx->tctx.luks->crypt_disk, 
					header->key_bytes);
			if(r){
				*win_pos = i;
				r=1;
				goto end;
			}
		}else{
			memcpy(master_list[i], master.key, header->key_bytes);
		}

	}
		
	r=testkeyhash(master_list, numkeys, header->mk_digest_salt,
			header->mk_digest_iter, header->mk_digest, *win_pos);

end:
	/* clean the room */
	free(master.key);
	free(split.key);
	for(i=0;i<numkeys;i++){
		free(usrKeyshashed[i]);
	}
	free(usKeyshashed);
	if(!ctx->fast){
		for(i=0;i<numkeys;i++)
			free(master_list[i]);
		free(master_list);
	}

	return r;

}