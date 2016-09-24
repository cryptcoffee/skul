#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "decrypt.h"
#include "../../src/skul.h"
#include "luks.h"

int interface_selection(pheader *header,int *slot,int *slot_order, int *tot, 
		int key_sel);
int initfs(pheader *header, int *iv_mode, int *chain_mode, char *crypt_disk, 
		char *path, lkey_t *encrypted, int *slot);

int alloc_header(pheader *header){
	
	int i;
	
	if(!(header->magic = calloc(7,sizeof(char)))){
		errprint("malloc error\n");
		return 0;
	}
	if(!(header->cipher_name = calloc(33,sizeof(char)))){
		errprint("malloc error\n");
		return 0;
	}
	if(!(header->cipher_mode = calloc(33,sizeof(char)))){
		errprint("malloc error\n");
		return 0;
	}
	if(!(header->hash_spec = calloc(33,sizeof(char)))){
		errprint("malloc error\n");
		return 0;
	}
	if(!(header->mk_digest = calloc(LUKS_DIGESTSIZE,sizeof(char)))){
		errprint("malloc error\n");
		return 0;
	}
	if(!(header->mk_digest_salt = calloc(LUKS_SALTSIZE,sizeof(char)))){
		errprint("malloc error\n");
		return 0;
	}
	if(!(header->uuid = calloc(41,sizeof(char)))){
		errprint("malloc error\n");
		return 0;
	}

	/* keyslot field allocation */
	for(i=0;i<LUKS_NUMKEYS;i++){
		if(!(header->keyslot[i].salt = calloc(LUKS_SALTSIZE+1,sizeof(char)))){
			errprint("malloc error\n");
			return 0;
		}
	}
	return 1;
}


void freeheader(pheader *header){
	int i;

	debug_print("freeheader started\n");
	free((header->magic));
	debug_print("	->magic deallocated\n");
	free((header->cipher_name));
	debug_print("	->cipher_name deallocated\n");
	free(header->cipher_mode);
	debug_print("	->cipher_mode deallocated\n");
	free(header->hash_spec);
	debug_print("	->hash_spec deallocated\n");
	free(header->mk_digest);
	debug_print("	->mk_digest deallocated\n");
	free(header->mk_digest_salt);
	debug_print("	->mk_digest_salt deallocated\n");
	free(header->uuid);
	debug_print("	->uuid deallocated\n");
	for(i=0;i<LUKS_NUMKEYS;i++){
		free(header->keyslot[i].salt);
		debug_print("	->keyslot[%d]: salt deallocated\n",i);
	}
	
}

int LUKS_pheadercpy(pheader *dst, pheader *src){

	int i;

	dst->version = src->version;
	dst->payload_offset = src->payload_offset;
	dst->key_bytes = src->key_bytes;
	dst->mk_digest_iter = src->mk_digest_iter;

	memcpy(dst->magic, src->magic,  6*sizeof(unsigned char));
	memcpy(dst->cipher_name, src->cipher_name, 32*sizeof(unsigned char));
	memcpy(dst->cipher_mode, src->cipher_mode, 32*sizeof(unsigned char));
	memcpy(dst->hash_spec, src->hash_spec, 32*sizeof(unsigned char));
	memcpy(dst->mk_digest, src->mk_digest, LUKS_DIGESTSIZE*sizeof(unsigned char));
	memcpy(dst->mk_digest_salt, src->mk_digest_salt, LUKS_SALTSIZE*sizeof(unsigned char));
	memcpy(dst->uuid, src->uuid, 40*sizeof(unsigned char));

	/* key-slots */
	for(i=0; i<LUKS_NUMKEYS; i++){
		dst->keyslot[i].active = src->keyslot[i].active;
		dst->keyslot[i].iterations = src->keyslot[i].iterations;
		dst->keyslot[i].key_material_offset = src->keyslot[i].key_material_offset;
		dst->keyslot[i].stripes = src->keyslot[i].stripes;
		memcpy(dst->keyslot[i].salt, src->keyslot[i].salt, LUKS_SALTSIZE);
	}

	return 1;

}


int LUKS_init(LUKS_CTX *ctx, int pwd_default, int *num_pwds, int *pwd_ord, char *path, 
		usrp UP, int *attack_mode){

	int c,mod,i;

	ctx->encrypted.keylen = 32;
	if((ctx->encrypted.key=calloc(ctx->encrypted.keylen, sizeof(char)))==NULL){
		errprint("malloc error!\n");
		return 0;
	}
	if((ctx->crypt_disk = calloc(32,sizeof(char)))==NULL){
		errprint("malloc error\n");
		return 0;
	}


	if(!initfs(&(ctx->header), &(ctx->iv_mode), &(ctx->chain_mode), 
				ctx->crypt_disk, path, &(ctx->encrypted), ctx->slot)){
		return 0;
	}

	if(pwd_default){
		/* Default */
		pwd_ord = realloc(pwd_ord,8);
		for(i=0,c=0;i<8;i++){
			if(ctx->slot[i]){
				pwd_ord[c]=i;
				c++;
			}
		}
	}else{
		for(i=0,c=0; i<*num_pwds && i<8; i++){
			if(ctx->slot[pwd_ord[i]]){
				if(pwd_ord[i]>8 || pwd_ord[i]<0){
					errprint("Invalid keyslot.\nTry 'skul -h' for more information\n");
					return 0;
				}else{
					c++;
				}
			}else{
				errprint("Keyslot %d not enabled\n", pwd_ord[i]);
				return 0;
			}
		}
	}

	*num_pwds=c;
	if(*num_pwds==0){
		errprint("Cannot found any active keyslot.\nTry not specifying any keyslot with the -o option.\n");
		return 0;
	}

	mod = UP.SEL_MOD;
	if(mod>3 || mod<0){
		errprint("Invalid Attack mode selection.\nTry 'skul -h' for more information\n");
		return 0;
	}

	*attack_mode=mod;

	/* set the correct pbk_hash */
	if(strcmp(ctx->header.hash_spec, "sha1")==0){
		ctx->pbk_hash=SHA_ONE;
	}else if(strcmp(ctx->header.hash_spec, "sha256")==0){
		ctx->pbk_hash=SHA_TWO_FIVE_SIX;
	}else if(strcmp(ctx->header.hash_spec, "sha512")==0){
		ctx->pbk_hash=SHA_FIVE_ONE_TWO;
	}else if(strcmp(ctx->header.hash_spec, "ripemd160")==0){
		ctx->pbk_hash=RIPEMD;
	}else{
		errprint("Unsupported hash function\n");
		return 0;
	}

	return 1;

}

void LUKS_clean(LUKS_CTX *ctx){
	
	freeheader(&(ctx->header));
	free(ctx->encrypted.key);
	free(ctx->crypt_disk);
	free(ctx);

}

int LUKS_CTXcpy(LUKS_CTX *dst, LUKS_CTX *src){

	int i;

	dst->encrypted.keylen = src->encrypted.keylen;
	
	dst->iv_mode = src->iv_mode;
	dst->chain_mode = src->chain_mode;
	dst->pbk_hash = src->pbk_hash;

	for(i=0;i<8;i++){
		dst->slot[i] = src->slot[i];
	}

	if(!alloc_header(&(dst->header))){
		errprint("alloc_header error!\n");
		return 0;
	}

	if((dst->encrypted.key=calloc(src->encrypted.keylen, sizeof(char)))==NULL){
		errprint("malloc error!\n");
		return 0;
	}
	if((dst->crypt_disk = calloc(32,sizeof(char)))==NULL){
		errprint("malloc error\n");
		return 0;
	}


	LUKS_pheadercpy(&(dst->header), &(src->header));
	memcpy(dst->encrypted.key, src->encrypted.key, src->encrypted.keylen);
	memcpy(dst->crypt_disk, src->crypt_disk, 32);

	return 1;

}

int read_header(pheader *header, char *path, int *slot){

	FILE *disk;
	int i;

	if(!(disk=fopen(path,"rb+"))){
		errprint("cannot open file: %s\n",path);
		return 0;
	}

	/* read header */
	if(fread(header->magic,sizeof(char),6,disk)<6){
		return 0;
	}

	if(!uint16read(&header->version,disk)){
		return 0;
	}

	if(fread(header->cipher_name,sizeof(char),32,disk)<32){
		return 0;
	}
	
	if(fread(header->cipher_mode,sizeof(char),32,disk)<32){
		return 0;
	}
	
	if(fread(header->hash_spec,sizeof(char),32,disk)<32){
		return 0;
	}
	header->hash_spec[31]='\0'; 
	
	if(!uint32read(&header->payload_offset,disk)){
		return 0;
	}
	
	if(!uint32read(&header->key_bytes,disk)){
		return 0;
	}
	
	if(fread(header->mk_digest,sizeof(char),LUKS_DIGESTSIZE,disk)<LUKS_DIGESTSIZE){
		return 0;
	}
	
	if(fread(header->mk_digest_salt,sizeof(char),LUKS_SALTSIZE,disk)<LUKS_SALTSIZE){
		return 0;
	}
	
	if(!uint32read(&header->mk_digest_iter,disk)){
		return 0;
	}
	
	if(fread(header->uuid,sizeof(char),40,disk)<40){
		return 0;
	}
	

	/* read keyslots */
	for(i=0;i<LUKS_NUMKEYS;i++){
		if(!uint32read(&header->keyslot[i].active,disk)){
			return 0;
		}
		if(header->keyslot[i].active == LUKS_KEY_ENABLED){
			slot[i]=1;
		}else{
			slot[i]=0;
		}
			
		if(!uint32read(&header->keyslot[i].iterations,disk)){
			return 0;
		}
		
		if(fread(header->keyslot[i].salt,sizeof(char),LUKS_SALTSIZE,disk)<LUKS_SALTSIZE){
			return 0;
		}
		
		if(!uint32read(&header->keyslot[i].key_material_offset,disk)){
			return 0;
		}

		if(!uint32read(&header->keyslot[i].stripes,disk)){
			return 0;
		}
	}

	fclose(disk);
	return 1;
}

void print_header(pheader *header){

	int i;

	printf("Magic: ");
	for(i=0;i<4;i++){
		printf("%c",header->magic[i]);
	}
	printf(" %#02x %#02x",header->magic[4],header->magic[5]);
	printf("\n");
	printf("Version: %d\n",header->version);
	printf("Disk UUID: %s\n",header->uuid);
	printf("Cipher name: %s\n",header->cipher_name);
	printf("Cipher mode: %s\n",header->cipher_mode);
	printf("Hash Function: %s\n",header->hash_spec);
	printf("Master key len: %d byte (%d bit)\n",header->key_bytes, (header->key_bytes * 8));
/*	printf("MASTER KEY DIGEST: ");
	for(i=0;i<LUKS_DIGESTSIZE;i++){
		printf("%02x ",header->mk_digest[i]);
	}
	printf("\n");
	printf("MASTER KEY SALT: ");
	for(i=0;i<LUKS_SALTSIZE;i++){
		printf("%02x ",header->mk_digest_salt[i]);
	}
	printf("\n");*/
	printf("Iterations: %d\n",header->mk_digest_iter);

}

void print_keyslot(pheader *header,int slot){

/*	int j;*/

	printf("KEYSLOT %d: ",slot);
	if(header->keyslot[slot].active == LUKS_KEY_DISABLED){
		printf("INACTIVE\n");
	}else{
		printf("ACTIVE\n");
		printf("ITERATIONS: %d\n",header->keyslot[slot].iterations);
/*		printf("SALT: ");
		for(j=0;j<LUKS_SALTSIZE;j++){
			printf("%02x ",header->keyslot[slot].salt[j]);
		}
		printf("\n");
		printf("KEY MATERIAL OFFSET: %d sectors\n",header->keyslot[slot].key_material_offset);
		printf("Stripes: %d\n",header->keyslot[slot].stripes);*/
	}
	
}

void LUKS_print_header(LUKS_CTX *ctx){
	int i;

	print_header(&(ctx->header));
	for(i=0;i<8;i++){
		if(ctx->slot[i]){
			printf("\n");
			print_keyslot(&(ctx->header),0);
		}
	}
}



int read_disk(unsigned char *dst, size_t size, char *path, size_t offset){
	
	FILE *file;

	if(!(file=fopen(path,"rb+"))){
		perror("fopen");
		return 0;
	}

	fseek(file, offset, SEEK_SET);
	if(fread(dst,sizeof(char),size,file)<size){
		if(feof(file)){
			fprintf(stderr,"EOF ERROR!\n");
		}
		if(ferror(file)){
			fprintf(stderr,"ferror(file)\n");
		}
		fprintf(stderr,"fread error!\n");
		return 0;
	}

	fclose(file);
	return 1;
}

int initfs(pheader *header, int *iv_mode, int *chain_mode, char *crypt_disk, 
		char *path, lkey_t *encrypted, int *slot){

	const unsigned char LUKS_MAGIC[6] = {'L','U','K','S',0xBA,0xBE};
	/* header initializations */
	if(!(alloc_header(header))){
		errprint("error in header allocation!\n");
		exit(EXIT_FAILURE);
	}
	debug_print("luks header allocated\n");

	/* read the header */
	if(!(read_header(header,path, slot))){
		errprint("error reading header\n");
		exit(EXIT_FAILURE);
	}
	debug_print("read header done\n");

	if(memcmp(header->magic, LUKS_MAGIC, 6) != 0){
		errprint("Not a LUKS disk!\n");
		exit(EXIT_FAILURE);
	}
	debug_print("LUKS MAGIC ok\n");
	
	/* check cipher mode */
	if(!check_mode(header->cipher_mode, iv_mode, chain_mode)){
		errprint("unsupported cipher_mode!\n");
		exit(EXIT_FAILURE);
	}
	debug_print("cipher mode ok\n");

	/* just read a little piece of disk */
	if(!(read_disk(crypt_disk, 32, path, header->payload_offset*SECTOR_SIZE))){
		errprint("error reading disk\n");
		exit(EXIT_FAILURE);
	}
	debug_print("read encrypted disk done\n");
	
	/* Read the encrypted MasterKey from partition 
	 * encryptedKey ← read from partition at
	 * 						 ks.key−material−offset and length
	 * 						 masterKeyLength × ks.stripes
	 * */
	encrypted->keylen = header->key_bytes * LUKS_STRIPES;
	encrypted->key = calloc(encrypted->keylen, sizeof(char));

	if(!(read_disk(encrypted->key,
					encrypted->keylen,path,
					header->keyslot[0].key_material_offset*SECTOR_SIZE))){
		errprint("error reading encryptedKey\n");
		exit(EXIT_FAILURE);
	}
	debug_print("read encrypted master key done\n");

	return 1;
}
