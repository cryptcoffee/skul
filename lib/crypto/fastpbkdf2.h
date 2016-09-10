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



/*
 * fastpbkdf2 - Faster PBKDF2-HMAC calculation
 * Written in 2015 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef FASTPBKDF2_H
#define FASTPBKDF2_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Calculates PBKDF2-HMAC-SHA1.
 *
 *  @p npw bytes at @p pw are the password input.
 *  @p nsalt bytes at @p salt are the salt input.
 *  @p iterations is the PBKDF2 iteration count and must be non-zero.
 *  @p nout bytes of output are written to @p out.  @p nout must be non-zero.
 *
 *  This function cannot fail; it does not report errors.
 */
void fastpbkdf2_hmac_sha1(const uint8_t *pw, size_t npw,
                          const uint8_t *salt, size_t nsalt,
                          uint32_t iterations,
                          uint8_t *out, size_t nout);

/** Calculates PBKDF2-HMAC-SHA256.
 *
 *  @p npw bytes at @p pw are the password input.
 *  @p nsalt bytes at @p salt are the salt input.
 *  @p iterations is the PBKDF2 iteration count and must be non-zero.
 *  @p nout bytes of output are written to @p out.  @p nout must be non-zero.
 *
 *  This function cannot fail; it does not report errors.
 */
void fastpbkdf2_hmac_sha256(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout);

/** Calculates PBKDF2-HMAC-SHA512.
 *
 *  @p npw bytes at @p pw are the password input.
 *  @p nsalt bytes at @p salt are the salt input.
 *  @p iterations is the PBKDF2 iteration count and must be non-zero.
 *  @p nout bytes of output are written to @p out.  @p nout must be non-zero.
 *
 *  This function cannot fail; it does not report errors.
 */
void fastpbkdf2_hmac_sha512(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout);

#ifdef __cplusplus
}
#endif

#endif
