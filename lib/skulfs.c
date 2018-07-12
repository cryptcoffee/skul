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



#include "skulfs.h"
#include "utils.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "alloclib.h"
#include "decrypt.h"
#include <string.h>

#define DEBUG 0 

static int uint32read(uint32_t *res, FILE *stream){

	uint8_t uint0,uint1,uint2,uint3;
	int r=1;

	if(fread(&uint0,sizeof(uint8_t),1,stream)<1){
		r=0;
		goto end;
	}
	if(fread(&uint1,1,sizeof(uint8_t),stream)<1){
		r=0;
		goto end;
	}
	if(fread(&uint2,1,sizeof(uint8_t),stream)<1){
		r=0;
		goto end;
	}
	if(fread(&uint3,1,sizeof(uint8_t),stream)<1){
		r=0;
		goto end;
	}
	*res = uint0 << 24 | uint1 << 16 | uint2 << 8 | uint3;

end:
	if(r == 0){
		res = NULL;
	}
	return r;
}

static int uint16read(uint16_t *res, FILE *stream){

	uint8_t uint0,uint1;

	if(fread(&uint0,1,sizeof(uint8_t),stream)<1){
		res = NULL;
		return 0;
	}
	if(fread(&uint1,1,sizeof(uint8_t),stream)<1){
		res = NULL;
		return 0;
	}
	*res = uint0 << 8 | uint1;
	return 1;
}

int read_header(pheader *header, char *path, int *slot){

	FILE *disk;
	int i;

	if(!(disk=fopen(path,"rb+"))){
		perror("fopen");
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
	/* Allocation of keyslots can happen only 
	 * once we have the key_bytes field */
	if(!alloc_keyslots(header)){
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

	printf("Disk UUID:         %s\n",header->uuid);
	printf("Magic:             ");
	for(i=0;i<4;i++){
		printf("%c",header->magic[i]);
	}
	printf(" %#02x %#02x",header->magic[4],header->magic[5]);
	printf("\n");
	printf("Version:           %d\n",header->version);
	printf("Cipher name:       %s\n",header->cipher_name);
	printf("Cipher mode:       %s\n",header->cipher_mode);
	printf("Hash spec:         %s\n",header->hash_spec);
	printf("Master key len:    %d byte (%d bit)\n",header->key_bytes, (header->key_bytes * 8));
	printf("Master key digest: ");
	for(i=0;i<LUKS_DIGESTSIZE;i++){
		printf("%02x ",header->mk_digest[i]);
	}
	printf("\n");
	printf("Master key salt:   ");
	for(i=0;i<LUKS_SALTSIZE;i++){
		if(i==16){
			printf("\n                   ");
		}
		printf("%02x ",header->mk_digest_salt[i]);
	}
	printf("\n");
	printf("Iterations:        %d\n",header->mk_digest_iter);

}

void print_keyslot(pheader *header,int slot){

	int j;

	printf("KEYSLOT %d: ",slot);
	if(header->keyslot[slot].active == LUKS_KEY_DISABLED){
		printf("INACTIVE\n");
	}else{
		printf("ACTIVE\n");
		printf("\tIterations:            %d\n",header->keyslot[slot].iterations);
		printf("\tSalt:                  ");
		for(j=0;j<LUKS_SALTSIZE;j++){
			if(j==16){
				printf("\n\t                       ");
			}
			printf("%02x ",header->keyslot[slot].salt[j]);
		}
		printf("\n");
		printf("\tKey material offset:   %d sectors\n",header->keyslot[slot].key_material_offset);
		printf("\tStripes:               %d\n",header->keyslot[slot].stripes);
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
		char *path, int *slot){

	const unsigned char LUKS_MAGIC[6] = {'L','U','K','S',0xBA,0xBE};
	int i = 0;

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
		errprint("Expected magic: ");
		for(i=0;i<4;i++){
			printf("%c",LUKS_MAGIC[i]);
		}
		printf(" %#02x %#02x",LUKS_MAGIC[4],LUKS_MAGIC[5]);
		printf("\n");

		errprint("Found magic:    ");
		for(i=0;i<4;i++){
			printf("%c",header->magic[i]);
		}
		printf(" %#02x %#02x",header->magic[4],header->magic[5]);
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
	//encrypted->keylen = header->key_bytes * LUKS_STRIPES;
	//encrypted->key = calloc(encrypted->keylen, sizeof(char));

	for(i=0; i<LUKS_NUMKEYS; i++){
		if(header->keyslot[i].active != LUKS_KEY_DISABLED){
			if(!(read_disk(header->keyslot[i].encrypted.key,
								header->keyslot[i].encrypted.keylen, path,
								header->keyslot[i].key_material_offset*SECTOR_SIZE))){
				errprint("error reading encryptedKey for keyslot: %d\n",i);
				exit(EXIT_FAILURE);
			}
		}
	}
	

	return 1;
}
