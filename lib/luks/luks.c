#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "decrypt.h"
#include "../../src/skul.h"
#include "luks.h"

#define DEBUG 0 

int interface_selection(pheader *header,int *slot,int *slot_order, int *tot, 
		int key_sel);
int initfs(pheader *header, int *iv_mode, int *chain_mode, char *crypt_disk, 
		char *path, lkey_t *encrypted, int *slot);


int LUKS_pheadercpy(pheader *dst, pheader *src){

	int i;

	dst->version = src->version;
	dst->payload_offset = src->payload_offset;
	dst->key_bytes = src->key_bytes;
	dst->mk_digest_iter = src->mk_digest_iter;

	memcpy(&(dst->magic), &(src->magic),  6*sizeof(unsigned char));
	memcpy(&(dst->cipher_name), &(src->cipher_name), 32*sizeof(unsigned char));
	memcpy(&(dst->cipher_mode), &(src->cipher_mode), 32*sizeof(unsigned char));
	memcpy(&(dst->hash_spec), &(src->hash_spec), 32*sizeof(unsigned char));
	memcpy(&(dst->mk_digest), &(src->mk_digest), LUKS_DIGESTSIZE*sizeof(unsigned char));
	memcpy(&(dst->mk_digest_salt), &(src->mk_digest_salt), LUKS_SALTSIZE*sizeof(unsigned char));
	memcpy(&(dst->uuid), &(src->uuid), 40*sizeof(unsigned char));

	/* key-slots */
	for(i=0; i<LUKS_NUMKEYS; i++){
		dst->keyslot[i].active = src->keyslot[i].active;
		dst->keyslot[i].iterations = src->keyslot[i].iterations;
		dst->keyslot[i].key_material_offset = src->keyslot[i].key_material_offset;
		dst->keyslot[i].stripes = src->keyslot[i].stripes;
		memcpy(&(dst->keyslot[i].salt), &(src->keyslot[i].salt), LUKS_SALTSIZE);
	}

	return 1;

}


int LUKS_init(SKUL_CTX *ctx){

	int c,num,mod,i;

	ctx->target = LUKS;
	ctx->cpy_target_ctx = LUKS_CTXcpy;
	ctx->open_key = luks_open_key;
	ctx->clean_target_ctx = LUKS_clean;

	if(!(ctx->luks = calloc(1,sizeof(LUKS_CTX)))){
		errprint("calloc error\n");
		return 0;
	}

	if(!(ctx->luks->crypt_disk=calloc(32,sizeof(char)))){
		errprint("calloc error!\n");
		return 0;
	}
	/* Need refactor. Should pass only the SKUL_CTX */
	if(!initfs(&(ctx->luks->header), &(ctx->luks->iv_mode), &(ctx->luks->chain_mode), 
				ctx->luks->crypt_disk, ctx->path, &(ctx->luks->encrypted), ctx->luks->slot)){
		return 0;
	}

	/* Default */
	for(i=0,c=0;i<8;i++){
		if(ctx->luks->slot[i]){
			ctx->luks->slot_order[c]=i;
			c++;
		}
	}
	num = c;
	if(ctx->UP.SEL_MOD==4)
		mod = interface_selection(&ctx->luks->header,ctx->luks->slot,
				ctx->luks->slot_order, &num, ctx->UP.KEY_SEL);
	else
		mod = ctx->UP.SEL_MOD;
	if(mod>4 || mod<=0){
		printf("%d\n",ctx->UP.SEL_MOD);
		errprint("Invalid Attack mode selection in configure file\n");
		return 0;
	}

	ctx->attack_mode=mod;
	ctx->luks->slot_number=num;

	/* set the correct pbk_hash */
	if(strcmp(ctx->luks->header.hash_spec, "sha1")==0){
		ctx->luks->pbk_hash=SHA_ONE;
	}else if(strcmp(ctx->luks->header.hash_spec, "sha256")==0){
		ctx->luks->pbk_hash=SHA_TWO_FIVE_SIX;
	}else if(strcmp(ctx->luks->header.hash_spec, "sha512")==0){
		ctx->luks->pbk_hash=SHA_FIVE_ONE_TWO;
	}else if(strcmp(ctx->luks->header.hash_spec, "ripemd160")==0){
		ctx->luks->pbk_hash=RIPEMD;
	}else{
		errprint("Unsupported hash function\n");
		return 0;
	}

	ctx->num_pwds = ctx->luks->slot_number; 

	return 1;

}

void LUKS_clean(SKUL_CTX *ctx){
	
	freeheader(&(ctx->luks->header));
	free(ctx->luks->encrypted.key);
	free(ctx->luks->crypt_disk);
	free(ctx->luks);

}

int LUKS_CTXcpy(SKUL_CTX *dst, SKUL_CTX *src){

	int i;

	dst->luks->encrypted.keylen = src->luks->encrypted.keylen;
	
	dst->luks->iv_mode = src->luks->iv_mode;
	dst->luks->chain_mode = src->luks->chain_mode;
	dst->luks->pbk_hash = src->luks->pbk_hash;
	dst->luks->slot_number = src->luks->slot_number;
	dst->luks->cur_slot = src->luks->cur_slot;


	for(i=0;i<8;i++){
		dst->luks->slot[i] = src->luks->slot[i];
		dst->luks->slot_order[i] = src->luks->slot_order[i];
	}

	if(!alloc_header(&(dst->luks->header))){
		errprint("alloc_header error!\n");
		return 0;
	}

	if((dst->luks->encrypted.key=calloc(src->luks->encrypted.keylen, sizeof(char)))==NULL){
		errprint("malloc error!\n");
		return 0;
	}
	if((dst->luks->crypt_disk = calloc(32,sizeof(char)))==NULL){
		errprint("malloc error\n");
		return 0;
	}


	LUKS_pheadercpy(&(dst->luks->header), &(src->luks->header));

	memcpy(dst->luks->encrypted.key, src->luks->encrypted.key, src->luks->encrypted.keylen);

	memcpy(dst->luks->crypt_disk, src->luks->crypt_disk, 32);

	return 1;

}

int alloc_header(pheader *header){
	
	int i;
	
	if(!(header->magic = calloc(7,sizeof(char)))){
		fprintf(stderr,"malloc error\n");
		return 0;
	}
	if(!(header->cipher_name = calloc(33,sizeof(char)))){
		fprintf(stderr,"malloc error\n");
		return 0;
	}
	if(!(header->cipher_mode = calloc(33,sizeof(char)))){
		fprintf(stderr,"malloc error\n");
		return 0;
	}
	if(!(header->hash_spec = calloc(33,sizeof(char)))){
		fprintf(stderr,"malloc error\n");
		return 0;
	}
	if(!(header->mk_digest = calloc(LUKS_DIGESTSIZE,sizeof(char)))){
		fprintf(stderr,"malloc error\n");
		return 0;
	}
	if(!(header->mk_digest_salt = calloc(LUKS_SALTSIZE,sizeof(char)))){
		fprintf(stderr,"malloc error\n");
		return 0;
	}
	if(!(header->uuid = calloc(41,sizeof(char)))){
		fprintf(stderr,"malloc error\n");
		return 0;
	}

	/* keyslot field allocation */
	for(i=0;i<LUKS_NUMKEYS;i++){
		if(!(header->keyslot[i].salt = calloc(LUKS_SALTSIZE+1,sizeof(char)))){
			fprintf(stderr,"malloc error\n");
			return 0;
		}
	}
	return 1;
}

void freeheader(pheader *header){
	int i;

	if(DEBUG){
		fprintf(stderr,"freeheader started\n");
	}
	free((header->magic));
	if(DEBUG)
		fprintf(stderr,"	->magic deallocated\n");
	free((header->cipher_name));
	if(DEBUG)
		fprintf(stderr,"	->cipher_name deallocated\n");
	free(header->cipher_mode);
	if(DEBUG)
		fprintf(stderr,"	->cipher_mode deallocated\n");
	free(header->hash_spec);
	if(DEBUG)
		fprintf(stderr,"	->hash_spec deallocated\n");
	free(header->mk_digest);
	if(DEBUG)
		fprintf(stderr,"	->mk_digest deallocated\n");
	free(header->mk_digest_salt);
	if(DEBUG)
		fprintf(stderr,"	->mk_digest_salt deallocated\n");
	free(header->uuid);
	if(DEBUG)
		fprintf(stderr,"	->uuid deallocated\n");
	for(i=0;i<LUKS_NUMKEYS;i++){
		free(header->keyslot[i].salt);
		if(DEBUG)
			fprintf(stderr,"	->keyslot[%d]: salt deallocated\n",i);
	}
	
}



int interface_selection(pheader *header,int *slot,int *slot_order,int *tot, int key_sel){

	int continua,s,i,num_slot,n,invalid,mod;
	char *line, ch;

	invalid=0;
	continua=1;
	line=NULL;
	while(continua){

		system("clear");
		display_art_nosleep();
		print_header(header);
		printf("\nACTIVE KEYSLOTS:\n\n");
		num_slot=0;
		for(i=0;i<8;i++){
			if(slot[i]){
				slot_order[num_slot]=i;
				num_slot++;
				print_keyslot(header,i);
				printf("\n");
			}
		}

		if(invalid)
			printf("Invalid selection!");
		invalid=0;
		if(key_sel){
			printf("\nSelect keyslots to attack in the desired order (0,1,2):\n$ ");
			line = readline(stdin, &n);
			if(n<=0)
				continue;
			for(i=0;i<n;i+=2){
				sscanf(line+i,"%d,",&s);
				if(s<0 || s>7){
					invalid=1;
					break;
				}
				if(!slot[s]){
					invalid=1;
					break;
				}
			}
			if(invalid)
				continue;
			for(i=0;i<=n;i+=2){
				num_slot=0;
				sscanf(line+i,"%d",&s);
				slot_order[num_slot]=s;
				num_slot++;
			}
		}
		continua=0;
	}

	continua=1;
	while(continua){

		if(key_sel){
			system("clear");
			display_art_nosleep();
			print_header(header);
			printf("\nSELECTED KEYSLOTS: %d\n\n", num_slot);
			for(i=0;i<num_slot;i++){
				print_keyslot(header,slot_order[i]);
				printf("\n");
			}
		}
		else{
			system("clear");
			display_art_nosleep();
			print_header(header);
			printf("\nACTIVE KEYSLOTS:\n\n");
			for(i=0;i<8;i++){
				if(slot[i]){
					print_keyslot(header,i);
					printf("\n");
				}
			}

		
		}

		if(invalid)
			printf("Invalid selection!");
		invalid=0;
		printf("\nSelect attack mode:\n1) bruteforce\n2) password list\n3) password list and bruteforce\n$ ");
		ch = getchar();
		mod = atoi(&ch);
		if((mod!=3) && (mod!=1) && (mod!=2)){
			invalid=1;
			continue;
		}
		continua=0;
	}

	*tot=num_slot;
	free(line);
	return mod;
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

	/* read the header */
	if(!(read_header(header,path, slot))){
		errprint("error reading header\n");
		exit(EXIT_FAILURE);
	}
	if(memcmp(header->magic, LUKS_MAGIC, 6) != 0){
		errprint("Not a LUKS disk!\n");
		exit(EXIT_FAILURE);
	}
	
	/* check cipher mode */
	if(!check_mode(header->cipher_mode, iv_mode, chain_mode)){
		errprint("unsupported cipher_mode!\n");
		exit(EXIT_FAILURE);
	}

	/* just read a little piece of disk */
	if(!(read_disk(crypt_disk, 32, path, header->payload_offset*SECTOR_SIZE))){
		errprint("error reading disk\n");
		exit(EXIT_FAILURE);
	}
	
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

	return 1;
}
