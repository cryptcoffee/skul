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



#include"thread.h"
#include"utils.h"
#include "luks/decrypt.h"
#include<pthread.h>
#include<unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include<string.h>
#include <signal.h>

pthread_cond_t condition_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t condition_mutex = PTHREAD_MUTEX_INITIALIZER;

int thlist_datainit(thlist_data *arg, SKUL_CTX *ctx, int id, char **list, int num, 
		int max_l, int *progress, char *win_pwd){

	int i,l;

	arg->id=id;
	arg->num=num;
	arg->max_l=max_l;
	arg->progress=progress;
	arg->win_pwd=win_pwd;

	if(!SKUL_CTX_cpy(&(arg->ctx), ctx)){
		errprint("Error in SKUL CTX copy\n");
		return 0;
	}

	/* set the list of password for the curent thread */
	if((arg->list = calloc(num,sizeof(char *)))==NULL){
		errprint("malloc error\n");
		return 0;
	}

	for(i=0;i<num;i++){
		l=strlen(list[i]);
		if((arg->list[i]=calloc(l+1,sizeof(char)))==NULL){
			errprint("malloc error!\n");
			return 0;
		}
		memcpy(arg->list[i],list[i],l);
	}

	return 1;	
}

int thforce_datainit(thforce_data *arg, SKUL_CTX *ctx, int id, int start, int num,	
		int comb, int len, int set_len, char *set, int *progress,
		char *win_pwd){

	arg->id=id;
	arg->start=start;
	arg->num=num;
	arg->comb=comb;
	arg->len=len;
	arg->set_len=set_len;
	arg->progress=progress;
	arg->win_pwd=win_pwd;

	if(!SKUL_CTX_cpy(&(arg->ctx), ctx)){
		errprint("Error in SKUL CTX copy\n");
		return 0;
	}

	/* create a copy of the set for the current thread */
	if((arg->set = calloc(set_len,sizeof(char *)))==NULL){
		errprint("malloc error\n");
		return 0;
	}
	memcpy(arg->set, set, set_len);

	return 1;
}

void *th_force(void *param){

	thforce_data *d = (thforce_data *)param;
	char *guess;
	int i,n,k,found;

	if((guess = calloc(d->len+1,sizeof(char)))==NULL){
		errprint("malloc error!\n");
		return 0;
	}

	*(d->progress)=0;
	found=0;

	for (i=0;i<d->comb;i++) {
		n = i;
		guess[d->len-1]=d->set[d->start + (i % d->num)];
		n/= d->num;
		for (k=d->len-2; k>=0; k--){
			guess[k] = d->set[n % d->set_len]; 
			n /= d->set_len;
		}

		found = d->ctx.open_key(guess, d->len, &(d->ctx));
		
		*(d->progress)=*(d->progress) + 1;

		if(found){

			/* entering mutex section */
			pthread_mutex_lock(&condition_mutex);
			pthread_cond_signal(&condition_cond);

			memset(d->win_pwd,0,d->len);
			sprintf(d->win_pwd,"%s",guess);

			/* exiting mutex section */
			pthread_mutex_unlock(&condition_mutex);
			goto end;
		}
	}

end:
	free(guess);
	pthread_exit(NULL);
}

void *th_list(void *param){

	thlist_data *d = (thlist_data *)param;
	int j,len=0,found=0;
	*(d->progress)=0;
	
	for(j=0;j<d->num;j++){
		
		*(d->progress)= *(d->progress)+1;
		len = strlen(d->list[j]);
		found = luks_open_key(d->list[j], len, &(d->ctx));

		if(found){

			/* entering mutex section */
			pthread_mutex_lock(&condition_mutex);
			pthread_cond_signal(&condition_cond);
			
			memset(d->win_pwd,0,d->max_l);
			sprintf(d->win_pwd,"%s",d->list[j]);
			
			/* exiting mutex section */
			pthread_mutex_unlock(&condition_mutex);
			goto end;
		}
	}
end:
	for(j=0;j<d->num;j++){
		free(d->list[j]);
	}
	pthread_exit(NULL);
}

int th_control(int max_l, int count, pthread_t *threads, int num_th, 
		pheader *header, int *progress, char *win_pwd, int keyslot,int prg_bar){

	int perc=0,i,/*j,l=0,k=0,first=1,*/tot_prog=0;

	while(1){
		if(prg_bar){
			printf("\r");
			for(i=0;i<max_l+30;i++){
				printf(" ");
			}
			fflush(stdout);
	
			tot_prog=0;
			for(i=0;i<num_th;i++){
				tot_prog +=progress[i];
			}
			printf("\rTried: %d \t %3d%%",tot_prog,perc);
			fflush(stdout);
			perc = tot_prog*100/count;
		}

		if(win_pwd[0]!='\0'){
			printf("\n\nPassword found!!\nKeyslot: %d\nThe password is: %s\n\n",keyslot,win_pwd);
			return 1;
		}		

		if(tot_prog==count){
			perc = tot_prog*100/count;
			printf("\rTried: %d \t %3d%%",tot_prog,perc);
			fflush(stdout);
			printf("\n");
			return 0;
		}

		usleep(10000);
	}

}

int test_control(int max_l, int count, pthread_t *threads, int num_th, 
		pheader *header, int *progress, char *win_pwd, int keyslot, int prg_bar){

	int perc=0,i,/*j,l=0,k=0,first=1,*/tot_prog=0,found=0;

	while(1){
		if(prg_bar){
			fflush(stdout);
			printf("Tried: %d \t %3d\r",tot_prog,perc);
			fflush(stdout);
			perc = tot_prog*100/count;
		}

		tot_prog=0;
		for(i=0;i<num_th;i++){
			tot_prog +=progress[i];
		}
		if(win_pwd[0]!='\0'){
			if(found==0){
				printf("\n\nPassword found!!\nThe password is: %s\n\n",win_pwd);
				found=1;
			}
		}		

		if(tot_prog==count){
			perc = tot_prog*100/count;
			printf("\rTried: %d \t %3d%%",tot_prog,perc);
			fflush(stdout);
			return found;
		}

		usleep(10000);
	}

}

void *test_force(void *param){

	thforce_data *d = (thforce_data *)param;
	char *guess;
	int i,n,k,found;

	if((guess = calloc(d->len+1,sizeof(char)))==NULL){
		errprint("malloc error!\n");
		return 0;
	}

	*(d->progress)=0;
	found=0;

	for (i=0;i<d->comb;i++) {
		n = i;
		guess[0]=d->set[d->start + (i % d->num)];
		n/= d->num;
		for (k=1; k<d->len; k++){
			guess[k] = d->set[n % d->set_len]; 
			n /= d->set_len;
		}

		
		found = d->ctx.open_key(guess, d->len, &(d->ctx));
		
		*(d->progress)=*(d->progress) + 1;

		if(found){

			/* entering mutex section */
			pthread_mutex_lock(&condition_mutex);
			pthread_cond_signal(&condition_cond);

			memset(d->win_pwd,0,d->len);
			sprintf(d->win_pwd,"%s",guess);

			/* exiting mutex section */
			pthread_mutex_unlock(&condition_mutex);
		}
	}

	free(guess);
	pthread_exit(NULL);
}

void *test_list(void *param){

	thlist_data *d = (thlist_data *)param;
	int j,len=0,found=0;
	*(d->progress)=0;
	
	for(j=0;j<d->num;j++){
		
		*(d->progress)= *(d->progress)+1;
		len = strlen(d->list[j]);
		found = luks_open_key(d->list[j], len, &(d->ctx));

		if(found){

			/* entering mutex section */
			pthread_mutex_lock(&condition_mutex);
			pthread_cond_signal(&condition_cond);
			
			memset(d->win_pwd,0,d->max_l);
			sprintf(d->win_pwd,"%s",d->list[j]);
			
			/* exiting mutex section */
			pthread_mutex_unlock(&condition_mutex);
		}
	}

	for(j=0;j<d->num;j++){
		free(d->list[j]);
	}
	pthread_exit(NULL);
}


