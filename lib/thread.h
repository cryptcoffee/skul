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
	char *crypt_disk;
	int fast_check;
	int max_l;
	int keyslot;
	int *progress;
	char *win_pwd;
	int pbk_hash;

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
	char *crypt_disk;
	char *set;
	int fast_check;
	int keyslot;
	int *progress;
	char *win_pwd;
	int pbk_hash;

}thforce_data;

int thlist_datainit(thlist_data *arg, int id, char **list, int num, 
		pheader *header, int iv_mode, int chain_mode, char *crypt_disk, 
		int fast_check,int max_l, int keyslot, int *progress, char *win_pwd);

int thforce_datainit(thforce_data *arg, int id, int start, int num,
		int comb, int len, int set_len, pheader *header, int iv_mode,
		int chain_mode, char *crypt_disk, int fast_check, char *set, 
		int keyslot,int *progress, char *win_pwd);

int th_control(int max_l, int count, pthread_t *threads, int num_th, 
		pheader *header, int *progress, char *win_pwd, int keyslot, int prg_bar);

int test_control(int max_l, int count, pthread_t *threads, int num_th, 
		pheader *header, int *progress, char *win_pwd, int keyslot, int prg_bar);

void *th_list(void *param);

void *test_list(void *param);

void *th_force(void *param);

void *test_force(void *param);

#endif
