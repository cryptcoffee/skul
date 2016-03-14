#ifndef THREAD_H
#define THREAD_H

#define _GNU_SOURCE
#include"skulfs.h" 
#include<pthread.h>
	
typedef struct threadlist_data{

	int id;
	int num;
	char **list;
	pheader header;
	int iv_mode;
	int chain_mode;
	lkey_t encrypted;
	char *crypt_disk;
	int fast_check;
	int max_l;
	int keyslot;
	int *progress;
	char *win_pwd;

}thlist_data;

typedef struct threadforce_data{

	int id;
	int start;
	int num;
	int comb;
	int len;
	int set_len;
	pheader header;
	int iv_mode;
	int chain_mode;
	lkey_t encrypted;
	char *crypt_disk;
	char *set;
	int fast_check;
	int keyslot;
	int *progress;
	char *win_pwd;

}thforce_data;

int thlist_datainit(thlist_data *arg, int id, char **list, int num, 
		pheader *header, int iv_mode, int chain_mode, lkey_t *encrypted, 
		char *crypt_disk, int fast_check,int max_l, int keyslot, int *progress,
		char *win_pwd);

int thforce_datainit(thforce_data *arg, int id, int start, int num,
		int comb, int len, int set_len, pheader *header, int iv_mode,
		int chain_mode, lkey_t *encrypted, char *crypt_disk, 
		int fast_check, char *set, int keyslot,int *progress,
		char *win_pwd);

int th_control(int max_l, int count, pthread_t *threads, int num_th, 
		pheader *header, int *progress, char *win_pwd, int keyslot, int prg_bar);

int test_control(int max_l, int count, pthread_t *threads, int num_th, 
		pheader *header, int *progress, char *win_pwd, int keyslot, int prg_bar);

void *th_list(void *param);

void *test_list(void *param);

void *th_force(void *param);

void *test_force(void *param);

#endif
