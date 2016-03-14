#include "alloclib.h"
#include "utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define DEBUG 0 

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
	if(!(header->hash_spec = calloc(32,sizeof(char)))){
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
		if(!(header->keyslot[i].salt = calloc(LUKS_SALTSIZE,sizeof(char)))){
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

char *readline(FILE *f, int *max_l){
	
	char *p,c;
	int size=2, n=0;
	

	if(!(p=calloc(size,sizeof(char)))){
		errprint("calloc error\n");
		return NULL;
	}
	while((c=fgetc(f)) != EOF){
		
		if(n>=size){
			size*=2;
			if(!(p=realloc(p,size))){
				errprint("realloc error\n");
			}
		}
		if(c=='\n'){
			p[n]='\0';
			break;
		}
		p[n]=c;
		n++;
	}
	*max_l = n;
	if(c==EOF){
		return NULL;
	}
	return (p?p:NULL);
}

