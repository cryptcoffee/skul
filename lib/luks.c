#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/utils.h"
#include "../lib/alloclib.h"
#include "../lib/decrypt.h"
#include "../src/skul.h"
#include "luks.h"


int interface_selection(pheader *header,int *slot,int *slot_order, int *tot, 
		int key_sel);

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
	ctx->cpytarget_ctx = LUKS_CTXcpy;
	ctx->open_key = luks_open_key;

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


