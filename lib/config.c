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



#include "config.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "alloclib.h"

int read_cfg(usrp *UP){

	FILE *conf;
	char *line,par[10];
	int count,i,val,n;

	if(!(conf = fopen("conf/skul.cfg","r"))){
		if(!(conf = fopen("../conf/skul.cfg","r"))){
			perror("fopen");
			return 0;
		}
	}
	/* default */
	UP->MIN_LEN=2;
	UP->MAX_LEN=16;
	UP->NUM_THR=1;
	UP->ALP_SET=1;
	UP->FST_CHK=1;
	UP->KEY_SEL=0;
	UP->SEL_MOD=1;

	count = 0;
	while((line = readline(conf,&n))){
		count++;
		if((line[0]!='#')&&(line[0]!='\0')&&(n<=10)){
			if((i=sscanf(line,"%s %d",par, &val))<2){
				fprintf(stderr,"skul: skul.cfg error: value not set on line %d\n",count);
				return 0;
			}
			par[7]='\0';
			if(memcmp(par,"MIN_LEN",7)==0){
				UP->MIN_LEN=val;
			}else if(memcmp(par,"MAX_LEN",7)==0){
				UP->MAX_LEN=val;
			}else if(memcmp(par,"NUM_THR",7)==0){
				UP->NUM_THR=val;
			}else if(memcmp(par,"ALP_SET",7)==0){
				UP->ALP_SET=val;
			}else if(memcmp(par,"FST_CHK",7)==0){
				UP->FST_CHK=val;
			}else if(memcmp(par,"KEY_SEL",7)==0){
				UP->KEY_SEL=val;
			}else if(memcmp(par,"SEL_MOD",7)==0){
				UP->SEL_MOD=val;
			}else if(memcmp(par,"PRG_BAR",7)==0){
				UP->PRG_BAR=val;
			}else{
				fprintf(stderr,"skul: skul.cfg error: invalid line %d\n",count);
				fclose(conf);
				return 0;
			}
		}
		free(line);
		line=NULL;
	}

	fclose(conf);
	return 1;
}

