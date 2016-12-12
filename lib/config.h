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


#ifndef CONFIG_H
#define CONFIG_H

#define UNSET 99

typedef enum{
	CPU,
	CUDA,
	CUDA_CPU
}engine_t;

typedef struct usr_preferences{
	int MIN_LEN;
	int MAX_LEN;
	int NUM_THR;
	int ALP_SET;
	int FST_CHK;
	int SEL_MOD;
	int PRG_BAR;
	int ENG_SEL;
	int CUD_BLK;
	int CUD_THR;
}usrp;

int read_cfg(usrp *UP, int threads, char *cfg_path, int mode, int fast, engine_t *engine);

#endif
