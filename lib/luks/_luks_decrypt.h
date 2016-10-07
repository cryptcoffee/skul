
#ifndef LUKS_DECRYPT_
#define LUKS_DECRYPT_

#include "luks.h"
int decrypt_ECB(unsigned char *key, unsigned char *encrypted, int encrypted_length,
		unsigned char * decrypted, unsigned char *iv);
int decrypt_CBC(unsigned char *key, unsigned char *encrypted, int encrypted_length,
		unsigned char * decrypted, unsigned char *iv);
int decrypt_XTS(unsigned char *key, unsigned char *encrypted, int encrypted_length,
		unsigned char *decrypted, unsigned char *iv);

int set_essivkey(unsigned char *ivkey, 
		unsigned char *usrkey, int len);

int gen_essiv(unsigned char *key, unsigned char *ciphertext, 
		int *outlen, unsigned char *plaintext, 
		int length);
int gen_xtsiv(unsigned char *iv_salt, unsigned char *iv, 
		int *outlen, unsigned char *buff, int length);
int gen_plainiv(unsigned char *iv_salt, unsigned char *iv, 
		int *outlen, unsigned char *buff, int length);

int testkeyhash(LUKS_CTX *ctx, char *key, int keylen, char *salt, 
		int iterations, char *hash, char *hash_spec, int pbk_hash);
int cuda_testkeyhash(LUKS_CTX *ctx, unsigned char **key_list, int numkeys, char *salt, 
		int iterations, char *hash, int *win_pos, int *progress);
int testkeydecryption(LUKS_CTX *ctx, char *key, char *crypt_disk, int keylen);

#endif
