#include <sys/time.h>
#include <stdio.h>
#include "../src/skul.h"
#include "config.h"
#include "attacks.h"
#include "utils.h"

int cpu_engine(SKUL_CTX *ctx){

	char *set;
	int i,j,res=0,found=0, set_len;
	struct timeval t0,t1;
	unsigned long sec;


	set = NULL;
	switch(ctx->attack_mode){
		
		case 1: /* bruteforce */
			printf("Attack mode: Bruteforce\n\n");
			printf("Min len:     %d characters\n", ctx->UP.MIN_LEN);
			printf("Max len:     %d characters\n", ctx->UP.MAX_LEN);
			printf("Alphabet:    %d\n\n", ctx->UP.ALP_SET);
			if(ctx->prompt){
				printf("Press enter to start cracking!");
				getchar();
				printf("\n");
			}

			/* START GLOBAL TIMER */
			gettimeofday(&t0,NULL);

			set = init_set(&set_len,ctx->UP.ALP_SET); 
			for(j=0;j<ctx->num_pwds;j++){ /* use this loop to manage multiple 
											passphrases like keyslots in LUKS */

				ctx->cur_pwd = ctx->pwd_ord[j];
				for(i=ctx->UP.MIN_LEN; i<=ctx->UP.MAX_LEN; i++){
					if((res=bruteforce(i, set, set_len, ctx))){
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
			if(ctx->prompt){
				printf("Press enter to start cracking!");
				getchar();
				printf("\n");
			}

			/* START GLOBAL TIMER */
			gettimeofday(&t0,NULL);

			for(j=0;j<ctx->num_pwds;j++){ /* use this loop to manage multiple 
											passphrases like keyslots in LUKS */

				ctx->cur_pwd = ctx->pwd_ord[j];
				res=pwlist(ctx);
				if(res)
					break;
			}
			break;

		case 3:
			printf("Attack mode: Password List first, then Bruteforce\n\n");
			printf("Settings for Bruteforce:\n");
			printf("Min len:     %d characters\n", ctx->UP.MIN_LEN);
			printf("Max len:     %d characters\n", ctx->UP.MAX_LEN);
			printf("Alphabet:    %d\n\n", ctx->UP.ALP_SET);
			if(ctx->prompt){
				printf("Press enter to start cracking!");
				getchar();
				printf("\n");
			}

			/* START GLOBAL TIMER */
			gettimeofday(&t0,NULL);

			for(j=0;j<ctx->num_pwds;j++){ /* use this loop to manage multiple 
											 passphrases like keyslots in LUKS */

				ctx->cur_pwd = ctx->pwd_ord[j];
				/* first call pwlist */
				if(!(res=pwlist(ctx))){
					/* then call bruteforce */
					set = init_set(&set_len,ctx->UP.ALP_SET); 
					for(i=ctx->UP.MIN_LEN; i<=ctx->UP.MAX_LEN; i++){
						if((res=bruteforce(i, set, set_len, ctx))){
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

	if(ctx->attack_mode==1 || ctx->attack_mode==3){
		free(set);
	}

	return res;

}

#if CUDA
int cuda_engine(SKUL_CTX *ctx){

	return 1;
}
#endif

#if CUDA
int cuda_cpu_engine(SKUL_CTX *ctx){

	return 1;
}
#endif

int engine(SKUL_CTX *ctx){

	int ret=0;

	switch(ctx->engine){
		case(CPU):
			ret=cpu_engine(ctx);
			break;

#if CUDA
		case(CUDA):
			ret=cuda_engine(ctx);
			break;
		
		case(CUDA_CPU):
			ret=cuda_cpu_engine(ctx);

		default:
			errprint("Unknown engine\n");

	}
#endif

	return ret;
}
