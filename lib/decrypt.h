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

int decrypt(int mode, unsigned char *key, unsigned char *encryptedData, 
		int encryptedLength,unsigned int * length, 
		unsigned char *decryptedData, unsigned char *iv);

int set_essivkey(unsigned char *ivkey, unsigned char *usrkey, int len);

int gen_essiv(unsigned char *key, unsigned char *ciphertext, 
		int *outlen, unsigned char *plaintext, 
		int length);

int check_mode(unsigned char *cipher_mode, int *iv_mode, int *chain_mode);

int testkeyhash(char *key, int keylen, char *salt, 
		int iterations, char *hash, char *hash_spec);

int testkeydecryption(int mode, char *key, char *crypt_disk, int keylen);

int open_key(char *key, int keylen, pheader *header, int iv_mode,
		int chain_mode, lkey_t *encrypted, char *crypt_disk, 
		int quick_test, int keyslot);

#endif

