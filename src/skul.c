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
#include "../lib/utils.h"
#include "../lib/config.h"
#include "../lib/thread.h"
#include "../lib/attacks.h"
#include "skul.h"
#include "../lib/luks/decrypt.h"
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <sys/time.h>
#include <getopt.h>

int parse_ord(SKUL_CTX *ctx, char *pwd_ord){

	char c;
	int n,i=0,j=0,len;

	if(strlen(pwd_ord)%2==0){
		/*0,1,2, is incorrect. 0,1,2 is correct*/
		errprint("Incorrect password order format.\nTry 'skul -h' for more information.\n");
		return 0;
	}
	pwd_ord[strlen(pwd_ord)]='\n';
	len = strlen(pwd_ord)/2+1;
	ctx->pwd_ord = realloc(ctx->pwd_ord, len);

	c = pwd_ord[i];
	while(c!='\n'){
		if(i%2==0){
			n=c-'0';
			ctx->pwd_ord[j]=n;
			j++;
		}else{
			if(c!=','){
				errprint("Incorrect password order format.\nTry 'skul -h' for more information.\n");
				return 0;
			}
		}

		i++;
		c = pwd_ord[i];
	}
	ctx->num_pwds = i/2+1;
	ctx->pwd_default=0;

	return 1;
}

int main(int argc, char **argv){
	
	char *set, *cfg_path=NULL; 
	int i,set_len, j,res=0,threads=0, prompt=1, errflag=0,found=0;
	struct timeval t0,t1;
	unsigned long sec;
	FILE *f;
	SKUL_CTX ctx;


	SKUL_CTX_init(&ctx);

	set = NULL;
	/* check arguments */
	if(!(argv[1])){
		print_small_help();
		exit(EXIT_FAILURE);
	}

	while (1) {
		char c, choice;
		int arg;
		
		c = getopt(argc, argv, "hvm:c:t:nf:l:o:");
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

			case 'o':
				if(optarg[0]!='-'){
					if(!parse_ord(&ctx, optarg)){
						exit(EXIT_FAILURE);
					}
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
	if(!SKUL_CTX_init_target(&ctx, LUKS)){
		errprint("Error initializing LUKS\n");
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

				ctx.cur_pwd = ctx.pwd_ord[j];
				for(i=ctx.UP.MIN_LEN; i<=ctx.UP.MAX_LEN; i++){
					if((res=bruteforce(i, set, set_len, &ctx))){
						found=1;
						break;
					}
				}
				if(found)
					break;
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

				ctx.cur_pwd = ctx.pwd_ord[j];
				res=pwlist(&ctx);
				if(res)
					break;
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

				ctx.cur_pwd = ctx.pwd_ord[j];
				if(!(res=pwlist(&ctx))){
					/* then call bruteforce */
					set = init_set(&set_len,ctx.UP.ALP_SET); 
					for(i=ctx.UP.MIN_LEN; i<=ctx.UP.MAX_LEN; i++){
						if((res=bruteforce(i, set, set_len, &ctx))){
							found=1;
							break;
						}
					}
				}
				if(res || found)
					break;
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
	EVP_cleanup();

	ctx.clean_target_ctx(ctx.luks);
	if(ctx.attack_mode==1 || ctx.attack_mode==3){
		free(set);
	}
	
	if(res==0)
		return 1;

	return 0;
}

void SKUL_CTX_init(SKUL_CTX *ctx){

	ctx->attack_mode=UNSET;
	ctx->fast = UNSET;
	ctx->pwlist_path = NULL;
	ctx->path = NULL;
	
	// default.. for you ax :*
	ctx->pwd_default = 1;
	ctx->num_pwds = 1; 	
	ctx->pwd_ord = calloc(ctx->num_pwds, sizeof(int));
	ctx->pwd_ord[0] = 0;

}

int SKUL_CTX_init_target(SKUL_CTX *ctx, int target){
	
	switch(target){
		case LUKS:
			ctx->target = LUKS;
			ctx->init_target_ctx = LUKS_init;
			ctx->cpy_target_ctx = LUKS_CTXcpy;
			ctx->open_key = luks_open_key;
			ctx->clean_target_ctx = LUKS_clean;

			if(!(ctx->luks = calloc(1,sizeof(LUKS_CTX)))){
				errprint("calloc error\n");
				return 0;
			}

			if(!ctx->init_target_ctx(ctx->luks, ctx->pwd_default, &(ctx->num_pwds), 
					ctx->pwd_ord, ctx->path, ctx->UP, &(ctx->attack_mode))){
				errprint("Error initializing LUKS context\n");
				return 0;
			}
		break;

		//other cases...

	}

	return 1;

}

int SKUL_CTX_cpy(SKUL_CTX *dst, SKUL_CTX *src){

	dst->target = src->target;
	dst->init_target_ctx = src->init_target_ctx;
	dst->clean_target_ctx = src->clean_target_ctx;
	dst->cpy_target_ctx = src->cpy_target_ctx;
	dst->open_key = src->open_key;
	dst->UP = src->UP;
	dst->attack_mode = src->attack_mode;
	dst->fast = src->fast;
	dst->pwd_default = src->num_pwds;
	dst->num_pwds = src->num_pwds;
	dst->cur_pwd = src->cur_pwd;

	if((dst->pwd_ord = calloc(dst->num_pwds,sizeof(int)))==NULL){
		errprint("Malloc Error\n");
		return 0;
	}
	memcpy(dst->pwd_ord, src->pwd_ord, dst->num_pwds);

	if(src->pwlist_path){
		if((dst->pwlist_path = calloc(strlen(src->pwlist_path),sizeof(char)))==NULL){
			errprint("Malloc Error\n");
			return 0;
		}
		memcpy(dst->pwlist_path, src->pwlist_path, strlen(src->pwlist_path)*sizeof(char));
	}


	if(src->path){
		if((dst->path = calloc(strlen(src->path),sizeof(char)))==NULL){
			errprint("Malloc Error\n");
			return 0;
		}
		memcpy(dst->path, src->path, strlen(src->path)*sizeof(char));
	}

	if(!(dst->luks = calloc(1,sizeof(LUKS_CTX)))){
		errprint("calloc error\n");
		return 0;
	}

	src->cpy_target_ctx(dst->luks, src->luks);

	return 1;
}
