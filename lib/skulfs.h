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
		char *path, lkey_t *encrypted, int *slot);

#endif
