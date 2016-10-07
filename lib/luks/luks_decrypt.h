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



#ifndef _DECRYPT_H_
#define _DECRYPT_H_

#include "../../src/skul.h"
#include <openssl/evp.h>

#define SHA_ONE 1
#define SHA_TWO_FIVE_SIX 2
#define SHA_FIVE_ONE_TWO 3
#define RIPEMD 4

int check_mode(LUKS_CTX *ctx, unsigned char *cipher_mode, int *iv_mode, int *chain_mode);
int luks_open_key(char *key, int keylen, SKUL_CTX *ctx);
int luks_cuda_open_key(char **keys, int numkeys, SKUL_CTX *ctx, int *win_pos, int *progress);

#endif

