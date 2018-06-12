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
#include "utils.h"
#include "af.h"
#include "decrypt.h"
#include "skulfs.h"
#include "../src/skul.h"

#include "fastpbkdf2.h"


int decrypt(int mode, unsigned char *key, unsigned char *encryptedData, 
		int encryptedLength,unsigned int *length, 
		unsigned char *decryptedData, unsigned char *iv){

	int decryptedLength, lastDecryptLength = 0;

	/* Create and initialize the context */
	EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
	if (cipher == NULL) {
		printf("Unable to create new EVP_CIPHER_CTX structure\n");
		return 0;
	}
	
	decryptedLength = 0;
	lastDecryptLength = 0;

	/* Initialise the decryption operation.*/
	switch(mode){
		case ECB:
			if(1 != EVP_DecryptInit_ex(cipher, 
						EVP_aes_256_ecb(), NULL, key, NULL)){
				printf("Error setting aes\n");
			}
			break;
		case CBC:
			if(1 != EVP_DecryptInit_ex(cipher, 
						EVP_aes_256_cbc(), NULL, key, iv)){ 
				printf("Error setting aes\n");
			}
			break;
		case XTS:
			if(1 != EVP_DecryptInit_ex(cipher,
						EVP_aes_128_xts(),NULL,key,iv)){
				printf("Error setting aes\n");
			}
	}

	if(!EVP_CIPHER_CTX_set_padding(cipher, 0)){
		printf("This is so strange.. should always return 1\n");
	}

	if(!EVP_DecryptUpdate(cipher, 
				decryptedData, &decryptedLength, 
				encryptedData, encryptedLength)){
		printf("EVP_DecryptUpdate_ex error\n");
	}

	if(!EVP_DecryptFinal_ex(cipher, 
			decryptedData + decryptedLength, 
			&lastDecryptLength)){
		printf("EVP_DecryptFinal_ex error\n");
	}
	
	*length = decryptedLength + lastDecryptLength;
	
	EVP_CIPHER_CTX_free(cipher);
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

	/* Create and initialize the context */
	EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
	if (cipher == NULL) {
		printf("Unable to create new EVP_CIPHER_CTX structure\n");
		return 0;
	}

	outl = 0;
	lastDecryptLength = 0;

	/* Initialise the decryption operation. */
	if(1 != EVP_EncryptInit_ex(cipher, EVP_aes_256_ecb(), NULL, key, NULL)){ 
		printf("Error setting aes\n");
		r=0;
		goto end;
	}

	if(!EVP_CIPHER_CTX_set_padding(cipher, 0)){
		printf("This is so strange.. should always return 1\n");
	}

	if(!EVP_EncryptUpdate(cipher, 
				ciphertext, &outl, 
				plaintext, length)){
		printf("EVP_DecryptUpdate_ex error\n");
		r=0;
		goto end;
	}

	if(!EVP_EncryptFinal_ex(cipher, 
			plaintext + outl, 
			&lastDecryptLength)){
		printf("EVP_DecryptFinal_ex error\n");
		r=0;
		goto end;
	}
	
	*outlen = outl + lastDecryptLength;
	
end:

	EVP_CIPHER_CTX_free(cipher);
	return r;
}

int check_mode(unsigned char *cipher_mode, int *iv_mode, int *chain_mode){

	unsigned char *iv;

	*iv_mode = 0;
	*chain_mode = 0;

	/* if no '-' then ecb is used */
	if((iv = strstr(cipher_mode, "-"))==NULL){
		*iv_mode = ECB;
	}else{
	
		iv++;
		/* plain64 mode */
		if(strcmp(iv,"plain64") == 0){
			*iv_mode = PLAIN64;
		}

		/* plain mode */
		if(strcmp(iv,"plain")==0){
			*iv_mode = PLAIN;
		}
	
		/* ESSIV mode */
		if(strcmp(iv,"essiv:sha256") == 0 ){
			*iv_mode = ESSIV;
		}

		if(*iv_mode==0){
			errprint("iv generation mode not still supported\n");
			return 0;
		}

	}
	if(strncmp(cipher_mode,"ecb", 3)==0){
		*chain_mode = ECB;
		return 1;
	}

	if(strncmp(cipher_mode,"cbc", 3)==0){
		*chain_mode = CBC;
		return 1;
	}

	if(strncmp(cipher_mode,"xts", 3)==0){
		*chain_mode = XTS;
		return 1;
	}
	return 0;
}

int testkeyhash(char *key, int keylen, char *salt, 
		int iterations, char *hash, char *hash_spec, int pbk_hash){

	char *keyhash;
	int i;

	keyhash = calloc(LUKS_DIGESTSIZE,sizeof(char));

	switch(pbk_hash){
		case SHA_ONE:
			fastpbkdf2_hmac_sha1(
				key, 
				keylen,
				salt,
				LUKS_SALTSIZE,
				iterations, 
				keyhash,
				LUKS_DIGESTSIZE); 
			break;
			
		case SHA_TWO_FIVE_SIX:
			fastpbkdf2_hmac_sha256(
				key, 
				keylen,
				salt,
				LUKS_SALTSIZE,
				iterations, 
				keyhash,
				LUKS_DIGESTSIZE); 
			break;

		case SHA_FIVE_ONE_TWO:
			fastpbkdf2_hmac_sha512(
				key, 
				keylen,
				salt,
				LUKS_SALTSIZE,
				iterations, 
				keyhash,
				LUKS_DIGESTSIZE);
			break;
			
		/* No fastpbkdf2 support for ripemd */
		case RIPEMD:
			if(!(PKCS5_PBKDF2_HMAC(key, keylen, salt, LUKS_SALTSIZE,
						iterations, EVP_get_digestbyname(hash_spec), LUKS_DIGESTSIZE, keyhash))){
				errprint("PBKDF2 error\n");
				free(keyhash);
				return 0;
			}
			break;

	}

	i=memcmp(keyhash, hash, LUKS_DIGESTSIZE);

	free(keyhash);

	if(i==0)
		return 1;

	return 0;
}

int testkeydecryption(int mode, char *key, char *crypt_disk, int keylen){

	char *plain_disk,*xtsiv;
	int i,len;
	unsigned char cbciv[] = {	0x62, 0x62, 0x62, 0x62,
								0x62, 0x62, 0x62, 0x62,
								0x62, 0x62, 0x62, 0x62,
								0x62, 0x62, 0x62, 0x62	}; /*random IV*/

	unsigned char guess[16] = {	0x00, 0x00, 0x00, 0x00, 
								0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 
								0x00, 0x00, 0x00, 0x00	};

	plain_disk = calloc(32,sizeof(char));

	if(mode==XTS){
		if(!(xtsiv=calloc(64,sizeof(char)))){
			errprint("malloc error!\n");
			free(plain_disk);
			return 0;
		}
		decrypt(mode,key, crypt_disk, 16, &len, plain_disk, xtsiv);
		i=memcmp(plain_disk, guess, 16);
		free(xtsiv);
	}else{
		decrypt(mode,key, crypt_disk, 32, &len, plain_disk, cbciv);
		i=memcmp(plain_disk+16, guess, 16);
	}

	free(plain_disk);

	if(i!=0)
		return 0;

	return 1;
}

int open_key(char *key, int keylen, pheader *header, int iv_mode,
		int chain_mode, lkey_t *encrypted, char *crypt_disk, 
		int quick_test, int keyslot, int pbk_hash){
	
	unsigned char *iv_salt=NULL, *buff, *iv;
	unsigned int AFSectors, outl;
	uint32_t sec, sector;
	int j=0,r=0;
	lkey_t master, split, usrKey, usrKeyhashed;

	master.key = calloc(header->key_bytes+1, sizeof(char));
	master.keylen = header->key_bytes;
	split.key = calloc(encrypted->keylen, sizeof(char));
	split.keylen = encrypted->keylen;
	usrKey.key = key;
	usrKey.keylen = keylen;
	buff = calloc(AES_BLOCK_SIZE,sizeof(char));
	iv = NULL;

	/* 1) hash the password provided by user */	
	usrKeyhashed.key = calloc(header->key_bytes,sizeof(char));
	usrKeyhashed.keylen = header->key_bytes;

	switch(pbk_hash){
		case SHA_ONE:
			fastpbkdf2_hmac_sha1(
				usrKey.key, 
				usrKey.keylen,
				header->keyslot[keyslot].salt,
				LUKS_SALTSIZE,
				header->keyslot[keyslot].iterations, 
				usrKeyhashed.key,
				usrKeyhashed.keylen); 
			break;
			
		case SHA_TWO_FIVE_SIX:
			fastpbkdf2_hmac_sha256(
				usrKey.key, 
				usrKey.keylen,
				header->keyslot[keyslot].salt,
				LUKS_SALTSIZE,
				header->keyslot[keyslot].iterations, 
				usrKeyhashed.key,
				usrKeyhashed.keylen);
			break;

		case SHA_FIVE_ONE_TWO:
			fastpbkdf2_hmac_sha512(
				usrKey.key, 
				usrKey.keylen,
				header->keyslot[keyslot].salt,
				LUKS_SALTSIZE,
				header->keyslot[keyslot].iterations, 
				usrKeyhashed.key,
				usrKeyhashed.keylen);
			break;

		case RIPEMD:
			if(!(PKCS5_PBKDF2_HMAC(usrKey.key, 
							usrKey.keylen, header->keyslot[keyslot].salt,
							LUKS_SALTSIZE ,header->keyslot[keyslot].iterations, 
							EVP_get_digestbyname(header->hash_spec),
							usrKeyhashed.keylen,usrKeyhashed.key))){ 
				errprint("error hashing usrKey\n");
				r=0;
				goto end;
			}
	}

	/* 2) generate iv_salt if needed for key decryption */
	if(iv_mode == ESSIV){ 
	
		if(!(iv = calloc(1,AES_BLOCK_SIZE))){
			errprint("calloc error\n");
			r=0;
			goto end;
		}
			
		if(!(iv_salt = calloc(SHA256_DIGEST_LENGTH,sizeof(char)))){
			errprint("calloc error\n");
			r=0;
			goto end;
		}
	
		if(!(set_essivkey(iv_salt, usrKeyhashed.key, 32))){
			errprint("iv_setkey error\n");
			r=0;
			goto end;
		}
	
	}else if(chain_mode == XTS){
		if(!(iv = calloc(2,AES_BLOCK_SIZE))){
			errprint("calloc error\n");
			r=0;
			goto end;
		}
	}

	AFSectors = (int)(ceil((float)(encrypted->keylen) / SECTOR_SIZE));

	/* iv generation for each sector */
	for(sector=0; sector<AFSectors; sector++){
		memset(buff,0,AES_BLOCK_SIZE);
		sec = htobe32(sector);

		buff[0] = (sec >> 24) & 0xff;
		buff[1] = (sec >> 16) & 0xff;
		buff[2] = (sec >> 8) & 0xff;
		buff[3] = (sec ) & 0xff;

		switch(chain_mode){
			case CBC:
				switch(iv_mode){
					case ESSIV:
					if(!gen_essiv(iv_salt, iv, &j, buff, AES_BLOCK_SIZE)){
							errprint("gen_essiv error\n");
							r=0;
							goto end;
						}
						if(j != AES_BLOCK_SIZE){
							errprint("gen_essiv len error\n");
							r=0;
							goto end;
						}
						break;
					default:
						iv=buff;
				}
				break;
			case ECB:
				iv=buff;
				break;
			case XTS:
				snprintf(iv,AES_BLOCK_SIZE,"%s",buff);
				break;
			default:
				iv=buff;
		}

		/* 3) sector by sector decryption of masterkey */	
		if(!decrypt(chain_mode,usrKeyhashed.key, 
					encrypted->key+(sector*SECTOR_SIZE),
					SECTOR_SIZE,&outl,
					split.key+(sector*SECTOR_SIZE),iv)){
			errprint("decrypt error!!\n");
			r=0;
			goto end;
		}
		if(outl!=SECTOR_SIZE){
			errprint("\t[WARNING:] DecryptUpdate length non corresponding\n\taspected:%d, obtained:%d\n", 
					SECTOR_SIZE, outl);
			r=0;
			goto end;

		}
	}

	/* 4) Merge the decrypted masterKey */
	if(AF_merge(split.key,
					master.key,header->key_bytes,
					header->keyslot[keyslot].stripes, header->hash_spec)!=0){
		errprint("error merging decrypted masterKey\n");
		r=0;
		goto end;
	}

	/* 5) Test master key */
	if(quick_test){
		r=testkeydecryption(chain_mode, master.key, crypt_disk, 
				header->key_bytes);
	}else{
		r=testkeyhash(master.key, master.keylen, header->mk_digest_salt,
				header->mk_digest_iter, header->mk_digest,header->hash_spec, pbk_hash);
	}

end:
	/* clean the room */
	free(usrKeyhashed.key);
	free(master.key);
	free(split.key);
	free(buff);
	switch(chain_mode){
		case CBC:
			if(iv_mode==ESSIV){
				free(iv);
				free(iv_salt);
			}
			break;
		case ECB:
			break;
		case XTS:
			free(iv);
			break;
	}
	return r;
}
