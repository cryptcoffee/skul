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



#ifndef __ATTACKS_H__
#define __ATTACKS_H__

int bruteforce(int len, char *set, int set_len, pheader *header, 
		int iv_mode, int chain_mode, char *crypt_disk, int keyslot, 
		int num_thr, int fst_chk, int prg_bar);

int pwlist(pheader *header, int iv_mode, int chain_mode, 
		char *crypt_disk, int keyslot, int num_thr, int fst_chk, int prg_bar);

char *init_set(int *set_len, int id_set);

#endif
