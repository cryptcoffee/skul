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
#include "../lib/luks.h"
#include "skul.h"
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <sys/time.h>
#include <getopt.h>


int main(int argc, char **argv){
	
	char *set, *cfg_path=NULL; 
	int i,set_len, j,res=0,threads=0, prompt=1, errflag=0;
	struct timeval t0,t1;
	unsigned long sec;
	FILE *f;
	SKUL_CTX ctx;

	/* SKUL INIT FUNCTION? */
	ctx.attack_mode=UNSET;
	ctx.fast = UNSET;
	ctx.pwlist_path = NULL;
	/*---------------------*/

	set = NULL;
	/* check arguments */
	if(!(argv[1])){
		print_small_help();
		exit(EXIT_FAILURE);
	}

	while (1) {
		char c, choice;
		int arg;
		
		c = getopt(argc, argv, "hvm:c:t:nf:l:");
		if (c == -1) {
			break;
		}
		switch (c) {

			case 'h':
				print_help();
				return 2;

			case 'v':
				print_version();
				return 3;

			case 'c':
				if(optarg[0]!='-'){
					cfg_path=optarg;
				}else{
					errprint("option requires an argument -- '-%c'\n", c);
					errflag++;
				}
				break;

			case 't':
				arg=atoi(optarg);
				if(arg>0)
					threads=arg;
				else{
					errprint("illegal argument for option -- '-%c'\n", c);
					errflag++;
				}
				break;

			case 'm':
				arg=atoi(optarg);
				if(arg>0 && arg<=4){
					ctx.attack_mode=arg;
				}else{
					errprint("illegal argument for option -- '-%c'\n", c);
					errflag++;
				}
				break;

			case 'n':
				prompt=0;
				break;

			case 'f':
				choice=optarg[0];
				switch (choice){
					case 'y':
						ctx.fast=1;
						break;
					case 'n':
						ctx.fast=0;
						break;
					default:
					errflag++;
				}
				break;

			case 'l':
				if(optarg[0]!='-'){
					ctx.pwlist_path=optarg;
				}else{
					errprint("option requires an argument -- '-%c'\n", c);
					errflag++;
				}
				break;

			case ':':
				errprint("option '-%c' requires an argument\n", c);
				break;

			case '?':
			default:
				print_small_help();
				exit(EXIT_FAILURE);
		}
	}

	if(errflag){
		print_small_help();
		exit(EXIT_FAILURE);
	}

	if (optind >= argc) {
		print_small_help();
		exit(EXIT_FAILURE);
	}

	/* last argument must be the disk name */
	ctx.path=argv[argc-1];

	/* test pwlist file */
	if(ctx.pwlist_path){
		if(!(f=fopen(ctx.pwlist_path,"r"))){
			errprint("cannot open %s: %s\n",ctx.pwlist_path, strerror(errno));
			errprint("[FATAL] missing password list file\n");
			return 0;
		}else{
			fclose(f);
		}
	}

	/* read configuration file */
	if(!read_cfg(&ctx.UP, threads, cfg_path, ctx.attack_mode, ctx.fast)){
		errprint("[FATAL] missing or invalid configuration file\n");
		exit(EXIT_FAILURE);
	}

	system("clear");
	display_art();

	/* TODO: target selection based on user choice or header parsing goes here 
	 *
	 *
	 * */

	/* set prepare function */
	ctx.init = LUKS_init;

	/* calling the prepare function */
	if(!ctx.init(&ctx)){
		errprint("[FATAL] error initializing context\n");
		exit(EXIT_FAILURE);
	}

	/*TODO: print should be generic... */
	if(ctx.UP.SEL_MOD!=0){
		print_header(&ctx.luks->header);
		printf("\nATTACKING KEYSLOTS:\n\n");
		print_keyslot(&ctx.luks->header,0);
		printf("\n");
	}



	/* prepare OpenSSL */
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();

	printf("Threads:     %d\n", ctx.UP.NUM_THR);
	if(ctx.UP.FST_CHK)
		printf("Fast check:  Enabled\n");
	else
		printf("Fast check:  Disabled\n");


	switch(ctx.attack_mode){
		
		case 1: /* bruteforce */
			printf("Attack mode: Bruteforce\n\n");
			printf("Min len:     %d characters\n", ctx.UP.MIN_LEN);
			printf("Max len:     %d characters\n", ctx.UP.MAX_LEN);
			printf("Alphabet:    %d\n\n", ctx.UP.ALP_SET);
			if(prompt){
				printf("Press enter to start cracking!");
				getchar();
				printf("\n");
			}

			/* START GLOBAL TIMER */
			gettimeofday(&t0,NULL);

			set = init_set(&set_len,ctx.UP.ALP_SET); 
			for(j=0;j<ctx.num_pwds;j++){ /* use this loop to manage multiple 
											passphrases like keyslots in LUKS */

				ctx.cur_pwd = j;
				for(i=ctx.UP.MIN_LEN; i<=ctx.UP.MAX_LEN; i++){
					if((res=bruteforce(i, set, set_len, &ctx))){
						break;
					}
				}
			}
			break;

		case 2: /* pwlist */
			printf("Attack mode: Password List\n\n");
			if(prompt){
				printf("Press enter to start cracking!");
				getchar();
				printf("\n");
			}

			/* START GLOBAL TIMER */
			gettimeofday(&t0,NULL);

			for(j=0;j<ctx.num_pwds;j++){ /* use this loop to manage multiple 
											passphrases like keyslots in LUKS */

				ctx.cur_pwd = j;
				res=pwlist(&ctx);
			}
			break;

		case 3:
			/* first call pwlist */
			printf("Attack mode: Password List first, then Bruteforce\n\n");
			printf("Settings for Bruteforce:\n");
			printf("Min len:     %d characters\n", ctx.UP.MIN_LEN);
			printf("Max len:     %d characters\n", ctx.UP.MAX_LEN);
			printf("Alphabet:    %d\n\n", ctx.UP.ALP_SET);
			if(prompt){
				printf("Press enter to start cracking!");
				getchar();
				printf("\n");
			}

			/* START GLOBAL TIMER */
			gettimeofday(&t0,NULL);

			for(j=0;j<ctx.num_pwds;j++){ /* use this loop to manage multiple 
											passphrases like keyslots in LUKS */

				ctx.cur_pwd = j;
				if(!(res=pwlist(&ctx))){
					/* then call bruteforce */
					set = init_set(&set_len,ctx.UP.ALP_SET); 
					for(i=ctx.UP.MIN_LEN; i<=ctx.UP.MAX_LEN; i++){
						if((res=bruteforce(i, set, set_len, &ctx))){
							break;
						}
					}
				}
			}
			break;

		default:
			errprint("Invalid Attack mode - check command line options or configuration file\n");
			break;

	}

	/* STOP GLOBAL TIMER */
	gettimeofday(&t1,NULL);
	sec=t1.tv_sec-t0.tv_sec;
	printf("TOTAL TIME: ");
	print_time(sec);

	/* free memory */
	/* TODO: must be general */
	EVP_cleanup();
	free(ctx.luks->encrypted.key);
	freeheader(&ctx.luks->header);
	free(ctx.luks->crypt_disk);
	if(ctx.attack_mode==1 || ctx.attack_mode==3){
		free(set);
	}
	
	if(res==0)
		return 1;

	return 0;
}

int SKUL_CTX_cpy(SKUL_CTX *dst, SKUL_CTX *src){

	dst->target = src->target;
	dst->init = src->init;
	dst->clean = src->clean;
	dst->cpytarget_ctx = src->cpytarget_ctx;
	dst->UP = src->UP;
	dst->attack_mode = src->attack_mode;
	dst->fast = src->fast;
	dst->num_pwds = dst->num_pwds;
	
	if(src->pwlist_path){
		if((dst->pwlist_path = calloc(strlen(src->pwlist_path),sizeof(char)))==NULL){
			errprint("Malloc Error\n");
			return 0;
		}
		memcpy(&(dst->pwlist_path), &(src->pwlist_path), strlen(src->pwlist_path)*sizeof(char));
	}


	if(src->path){
		if((dst->path = calloc(strlen(src->path),sizeof(char)))==NULL){
			errprint("Malloc Error\n");
			return 0;
		}
		memcpy(&(dst->path), &(src->path), strlen(src->path)*sizeof(char));
	}

	src->init(dst);
	src->cpytarget_ctx(dst, src);

	return 1;
}
