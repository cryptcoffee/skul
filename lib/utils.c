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



#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdarg.h>
#include <unistd.h>

int errprint(const char *format, ...){

	va_list arg;
	int done;

	va_start(arg, format);
	fprintf(stderr,"skul: ");
	done = vfprintf(stderr, format, arg);
	fflush(stdout);
	va_end(arg);

	return done;
}

int dbgprint(int debug, const char *format, ...){

	va_list arg;
	int done;
	
	if(debug){
		va_start(arg, format);
		done = vfprintf(stdout,format,arg);
		va_end(arg);
		return done;
	}

	return 0;
}

uint32_t l2bEndian(uint32_t num){

uint32_t res=0, b0, b1, b2, b3;

b0 = (num & 0x000000ff) << 24u;
b1 = (num & 0x0000ff00) << 8u;
b2 = (num & 0x00ff0000) >> 8u;
b3 = (num & 0xff000000) >> 24u;
res = b0 | b1 | b2 | b3;

return res;
}

void display_art(){

	printf("\n");
	printf(" ██▓     █    ██  ▄████▄   ██▓ ██▓███   ██░ ██ ▓█████  ██▀███  \n");
	usleep(500000);
	printf("▓██▒     ██  ▓██▒▒██▀ ▀█  ▓██▒▓██░  ██▒▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒\n");
	usleep(500000);
	printf("▒██░    ▓██  ▒██░▒▓█    ▄ ▒██▒▓██░ ██▓▒▒██▀▀██░▒███   ▓██ ░▄█ ▒\n");
	usleep(500000);
	printf("▒██░    ▓▓█  ░██░▒▓▓▄ ▄██▒░██░▒██▄█▓▒ ▒░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄  \n");
	usleep(500000);
	printf("░██████▒▒▒█████▓ ▒ ▓███▀ ░░██░▒██▒ ░  ░░▓█▒░██▓░▒████▒░██▓ ▒██▒\n");
	usleep(500000);
	printf("░ ▒░▓  ░░▒▓▒ ▒ ▒ ░ ░▒ ▒  ░░▓  ▒▓▒░ ░  ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░\n");
	usleep(500000);
	printf("░ ░ ▒  ░░░▒░ ░ ░   ░  ▒    ▒ ░░▒ ░      ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░\n");
	usleep(500000);
	printf("  ░ ░    ░░░ ░ ░ ░         ▒ ░░░        ░  ░░ ░   ░     ░░   ░ \n");
	usleep(500000);
	printf("    ░  ░   ░     ░ ░       ░            ░  ░  ░   ░  ░   ░     \n");
	usleep(800000);
	printf("\n");
}
