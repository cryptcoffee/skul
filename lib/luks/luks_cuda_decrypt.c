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

int decrypt_ECB(unsigned char *key, unsigned char *encrypted, int encrypted_len
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

int decrypt_CBC(unsigned char *key, unsigned char *encrypted, int encrypted_len
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
	snprintf(iv,lenght,"%s",buff);
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



int luks_cuda_open_key(char **keys, int numkeys, SKUL_CTX *ctx, int *win_pos){ 
		
	unsigned char *buff, iv[2*AES_BLOCK_SIZE], iv_salt[SHA256_DIGEST_LENGTH];
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

	usrKeyshashed = calloc(numkeys,sizeof(char*));
	for(i=0;i<numkeys;i++){
		usrKeyshashed[i] = calloc( strlen(key[i]), sizeof(char));
	}

	/* 1) hash the password provided by user */	
	if(!(header->pbkdf2_funcion(keys, numkeys, header->keyslot[ctx->cur_pwd].salt,
						LUKS_SALTSIZE, header->keyslot[ctx->cur_pwd].iterations,
						userKeyshashed))){
		errprint("Error hashing user key");
		return 0;
	}
	
	for(i=0; i<numkeys; i++){

		if(ctx->tctx.luks->iv_mode == ESSIV){
			if(!(set_essivkey(iv_salt, usrKeyhashed.key, 32))){
				errprint("Error generating iv_salt");
				return 0;
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
				errprint("Error generating iv");
				return 0;
			}
	
			if(!header->decrypt(userKeyshashed[i],
						ctx->tctx.luks->encrypted.key+(sector*SECTOR_SIZE),
						SECTOR_SIZE,&outl, split.key+(sector*SECTOR_SIZE),iv)){
				errprint("Error decrypting masterkey");
				return 0;
			}
		}

		if(AF_merge(split.key,
					master.key,header->key_bytes,
					header->keyslot[ctx->cur_pwd].stripes, header->hash_spec)!=0){
			errprint("[WARNING] error merging decrypted masterKey\n");
			r=0;
			goto end;
		}
	
		/* 5) Test master key */
		if(ctx->fast){
			r=testkeydecryption(ctx->tctx.luks->chain_mode, master.key, ctx->tctx.luks->crypt_disk, 
					header->key_bytes);
		}else{
			r=testkeyhash(master.key, master.keylen, header->mk_digest_salt,
					header->mk_digest_iter, header->mk_digest,header->hash_spec, ctx->tctx.luks->pbk_hash);
		}
		if(r){
			*win_pos = i;
			return 1;
		}

	}
	return 0;


	// understand where to do cleanup
end:
	/* clean the room */
	free(usrKeyhashed.key);
	free(master.key);
	free(split.key);
	free(buff);
	switch(ctx->tctx.luks->chain_mode){
		case CBC:
			if(ctx->tctx.luks->iv_mode==ESSIV){
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