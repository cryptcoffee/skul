#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/aes.h"
#include <endian.h>
#include "../lib/skulfs.h"
#include "../lib/utils.h"
#include "../lib/alloclib.h"
#include "../lib/decrypt.h"
#include "../lib/config.h"
#include "../lib/thread.h"
#include "../lib/attacks.h"
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <sys/time.h>

#define DEBUG 0
#define LOG 0
//#define TESTING

int interface_selection(pheader *header,int *slot,int *slot_order, int *tot, 
		int key_sel);

int main(int argc, char **argv){
	
	unsigned char *crypt_disk=NULL;
	char *path, *set; 
	pheader header;
	lkey_t encrypted;
	int iv_mode, chain_mode,i,set_len,num,j,c, mod;
	int slot[8], slot_order[8];
	usrp UP;

	set = NULL;
	
	/* check arguments */
	if(!(argv[1])){
		errprint("insert file name\n");
		exit(EXIT_FAILURE);
	}
	path = argv[1];

	/* read configuration file */
	if(!read_cfg(&UP)){
		errprint("missing or invalid configuration file\n");
		exit(EXIT_FAILURE);
	}

	if(!(crypt_disk=calloc(32,sizeof(char)))){
		errprint("calloc error!\n");
		exit(EXIT_FAILURE);
	}
	if(!initfs(&header, &iv_mode, &chain_mode, crypt_disk, path, 
				&encrypted,	slot)){
		exit(EXIT_FAILURE);
	}

	if(UP.SEL_MOD==0){
		system("clear");
	}else{
		print_header(&header);
		printf("\nATTACKING KEYSLOTS:\n\n");
		print_keyslot(&header,0);
		printf("\n");
	}
/*	display_art();*/

	/* Default */
	for(i=0,c=0;i<8;i++){
		if(slot[i]){
			slot_order[c]=i;
			c++;
		}
	}
	num = c;
	if(!UP.SEL_MOD)
		mod = interface_selection(&header,slot,slot_order,&num, UP.KEY_SEL);
	else
		mod = UP.SEL_MOD;
	if(mod>3){
		errprint("Invalid Attack mode selection in configure file\n");
		exit(EXIT_FAILURE);
	}

	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();

	switch(mod){
		
		case 1: /* bruteforce */
			set = init_set(&set_len,UP.ALP_SET); 
			for(j=0;j<num;j++){
				for(i=UP.MIN_LEN;i<=UP.MAX_LEN;i++){
					if(bruteforce(i, set, set_len, &header, iv_mode, 
								chain_mode, &encrypted, crypt_disk,
									slot_order[j],UP.NUM_THR,UP.FST_CHK,UP.PRG_BAR)){
						break;
					}
				}
			}
			break;

		case 2: /* pwlist */
			for(j=0;j<num;j++){
				pwlist(&header, iv_mode, chain_mode, &encrypted, crypt_disk,
						slot_order[j],UP.NUM_THR,UP.FST_CHK,UP.PRG_BAR);
			}
			break;

		case 3:
			/* first call pwlist */
			for(j=0;j<num;j++){
				if(!pwlist(&header, iv_mode, chain_mode, &encrypted, crypt_disk,
							slot_order[j],UP.NUM_THR,UP.FST_CHK,UP.PRG_BAR)){
					/* then call bruteforce */
					set = init_set(&set_len,UP.ALP_SET); 
					for(i=UP.MIN_LEN;i<=UP.MAX_LEN;i++){
						if(bruteforce(i, set, set_len, &header, iv_mode, 
									chain_mode, &encrypted, crypt_disk, 
									slot_order[j],UP.NUM_THR,UP.FST_CHK,UP.PRG_BAR)){
							break;
						}
					}
				}
			}
			break;

		default:
			printf("invalid\n");
			break;

	}

	/* free memory */
	EVP_cleanup();
	free(encrypted.key);
	freeheader(&header);
	free(crypt_disk);
	if(mod==1||mod==3){
		free(set);
	}
	
	return 0;
}

int interface_selection(pheader *header,int *slot,int *slot_order,int *tot, int key_sel){

	int continua,s,i,num_slot,n,invalid,mod;
	char *line, ch;

	invalid=0;
	continua=1;
	line=NULL;
	while(continua){

		system("clear");
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
			print_header(header);
			printf("\nSELECTED KEYSLOTS: %d\n\n", num_slot);
			for(i=0;i<num_slot;i++){
				print_keyslot(header,slot_order[i]);
				printf("\n");
			}
		}
		else{
			system("clear");
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