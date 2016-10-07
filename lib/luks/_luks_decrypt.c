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
#include "luks_decrypt.h"
#include "../../src/skul.h"
#include "../crypto/af.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>


int decrypt_ECB(unsigned char *key, unsigned char *encrypted, int encrypted_length,
		unsigned char * decrypted, unsigned char *iv){
	int decrypted_length, lastDecryptLength = 0;
	EVP_CIPHER_CTX cipher;

	decrypted_length = 0;
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
				decrypted, &decrypted_length, 
				encrypted, encrypted_length)){
		errprint("EVP_DecryptUpdate_ex error\n");
		return 0;
	}

	if(!EVP_DecryptFinal_ex(&cipher, 
			decrypted + decrypted_length, 
			&lastDecryptLength)){
		errprint("EVP_DecryptFinal_ex error\n");
		return 0;
	}
	
	EVP_CIPHER_CTX_cleanup(&cipher);
	return 1;


}

int decrypt_CBC(unsigned char *key, unsigned char *encrypted, int encrypted_length,
		unsigned char *decrypted, unsigned char *iv){

	int decrypted_length, lastDecryptLength = 0;
	EVP_CIPHER_CTX cipher;

	decrypted_length = 0;
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
				decrypted, &decrypted_length, 
				encrypted, encrypted_length)){
		errprint("EVP_DecryptUpdate_ex error\n");
		return 0;
	}

	if(!EVP_DecryptFinal_ex(&cipher, 
			decrypted + decrypted_length, 
			&lastDecryptLength)){
		errprint("EVP_DecryptFinal_ex error\n");
		return 0;
	}
	
	EVP_CIPHER_CTX_cleanup(&cipher);
	return 1;

}

int decrypt_XTS(unsigned char *key, unsigned char *encrypted, int encrypted_length,
		unsigned char *decrypted, unsigned char *iv){

	int decrypted_length, lastDecryptLength = 0;
	EVP_CIPHER_CTX cipher;

	decrypted_length = 0;
	lastDecryptLength = 0;

	EVP_CIPHER_CTX_init(&cipher);

	if(1 != EVP_DecryptInit_ex(&cipher, 
				EVP_aes_128_xts(), NULL, key, iv)){
		errprint("Error setting aes\n");
		return 0;
	}

	if(!EVP_CIPHER_CTX_set_padding(&cipher, 0)){
		errprint("This is so strange.. set padding should always return 1\n");
		return 0;
	}

	if(!EVP_DecryptUpdate(&cipher, 
				decrypted, &decrypted_length, 
				encrypted, encrypted_length)){
		errprint("EVP_DecryptUpdate_ex error\n");
		return 0;
	}

	if(!EVP_DecryptFinal_ex(&cipher, 
			decrypted + decrypted_length, 
			&lastDecryptLength)){
		errprint("EVP_DecryptFinal_ex error\n");
		return 0;
	}
	
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
	*outlen = length;

	return 1;

}

int gen_plainiv(unsigned char *iv_salt, unsigned char *iv, 
		int *outlen, unsigned char *buff, int length){

	// plain iv doesn't use salt
	memcpy(iv, buff, length);
	*outlen = length;

	return 1;
}

int testkeyhash(LUKS_CTX *ctx, char *key, int keylen, char *salt, 
		int iterations, char *hash){

	char keyhash[LUKS_DIGESTSIZE];
	int i;

	ctx->pbkdf2_function(key, keylen, salt, LUKS_SALTSIZE, 
				iterations, keyhash, LUKS_DIGESTSIZE);


	i=memcmp(keyhash, hash, LUKS_DIGESTSIZE);
	if(i!=0)
		return 0;

	return 1;
}


int cuda_testkeyhash(LUKS_CTX *ctx, unsigned char **key_list, int numkeys, char *salt, 
		int iterations, char *hash, int *win_pos, int *progress){

	uint8_t **keyhashes;
	int i,j,win=0;

	keyhashes = calloc(numkeys, sizeof(char *));
	for(i=0;i<numkeys;i++){
		keyhashes[i] = calloc(LUKS_DIGESTSIZE,sizeof(char));
	}

	if(!(ctx->cuda_pbkdf2_function(key_list, numkeys, salt,
						LUKS_SALTSIZE, iterations,
						keyhashes))){
		errprint("Error hashing user keys\n");
		win=0;
		goto end;
	}


	for(i=0;i<numkeys;i++){
		j=memcmp(keyhashes[i], hash, LUKS_DIGESTSIZE);
		if(j==0){ 
			*win_pos=i;
			win=1;
			break;
		}
		*progress = *progress + 1;
	}

end:
	for(i=0;i<numkeys;i++){
		free(keyhashes[i]);
	}
	free(keyhashes);

	return win;
}

int testkeydecryption(LUKS_CTX *ctx, char *key, char *crypt_disk, int keylen){

	char plain_disk[32];
	int i;

	unsigned char fake_iv[64] = {	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	unsigned char guess[16] = {		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	ctx->decrypt(key, crypt_disk, 32, plain_disk, fake_iv); 
	i=memcmp(plain_disk+16, guess, 16);

	if(i!=0)
		return 0;

	return 1;
}



