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
#include "../src/skul.h"
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdarg.h>
#include <unistd.h>

void print_help(){
#ifdef SKUL_FIX
	printf("Cryptcoffee - Skul %d.%d.%d\n", SKUL_MAJOR, SKUL_MINOR, SKUL_FIX);
#else
	printf("Cryptcoffee - Skul %d.%d\n", SKUL_MAJOR, SKUL_MINOR);
#endif
	printf("A PoC to bruteforce the Cryptsetup implementation of Linux Unified Key Setup (LUKS).\n");
	printf("See http://crypt.coffee/research/luks.html for more information.\n\n");
	printf("Usage: skul [-h] [-v] <filename>\n\n");
	printf("Options:\n");
	printf("   -h\tdisplay this help text and exit\n");
	printf("   -v\tdisplay version information and exit\n\n");
	printf("Filename:\n");
	printf("   The name of the file containing the LUKS encrypted partition.\n");
	printf("   For testing purposes Skul comes with an example cryptsetup's encrypted\n");
	printf("   partition header in the `disks/` directory.\n");
	printf("   To test your own disk you first need to dump the LUKS header of the partition:\n");
	printf("      # dd if=/dev/sdX of=./my_dump bs=1024 count=3072\n");
	printf("      # chown myusr:myusr ./my_dump\n");
	printf("   Then you can run:\n");
	printf("      $ skul ./my_dump\n\n");
	printf("Configuring Skul:\n");
	printf("   You can configure Skul through it's configuration file `conf/skul.cfg`\n\n");
	printf("** For BlackArch Linux users:\n");
	printf("   You can find the Skul directory at `/usr/share/skul`\n\n");
	printf("Report bugs to sha@crypt.coffee\n");
	printf("Cryptcoffee Skul home page: https://github.com/cryptcoffee/skul\n");
}

void print_small_help(){
	printf("Usage: skul [-h] [-v] <filename>\n");
	printf("Try 'skul -h' for more information.\n");
}

void print_version(){
#ifdef SKUL_FIX
	printf("Cryptcoffee - Skul %d.%d.%d\n", SKUL_MAJOR, SKUL_MINOR, SKUL_FIX);
#else
	printf("Cryptcoffee - Skul %d.%d\n", SKUL_MAJOR, SKUL_MINOR);
#endif
}

void print_format(unsigned long val){
	if(val==0)
		printf("00");
	else if(val<10)
		printf("0%lu",val);
	else
		printf("%lu",val);
}

void print_time(unsigned long sec){
	const unsigned int SECONDS_IN_A_DAY=86400;
	const unsigned int SECONDS_IN_AN_HOUR = 3600; 
	const unsigned int SECONDS_IN_A_MINUTE = 60;

	print_format((unsigned long)(sec/SECONDS_IN_A_DAY));
	printf("d ");
	print_format((unsigned long)((sec%SECONDS_IN_A_DAY)/SECONDS_IN_AN_HOUR));
	printf("h ");
	print_format((unsigned long)((sec%SECONDS_IN_AN_HOUR)/SECONDS_IN_A_MINUTE));
	printf("m ");
	print_format((unsigned long)((sec%SECONDS_IN_AN_HOUR)%SECONDS_IN_A_MINUTE));
	printf("s\n");

}

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

int debug_print(const char *format, ...){

#ifdef DEBUG
	va_list arg;
	int done;
	
		va_start(arg, format);
		done = vfprintf(stdout,format,arg);
		va_end(arg);
		return done;
#endif

	return 0;
}

int warn_print(const char *format, ...){

#ifdef WARN
	va_list arg;
	int done;
	
		va_start(arg, format);
		done = vfprintf(stdout,format,arg);
		va_end(arg);
		return done;
#endif

	return 0;
}


void dbgprintkey(uint8_t *key, int len, char *name){
	
#ifdef DEBUG
	int i;

	printf("%s: ", name);
	for(i=0;i<len;i++){
		printf("%02x ", key[i]);
	}
	printf("\n");
	fflush(stdout);

#endif

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

void print_art(int roundsleep, int finalsleep){
	
	printf("\n");
	printf("         --[ CRYPTCOFFEE ]--");
	printf("\n\n");
	usleep(roundsleep);
	printf("      ██████  ██ ▄█▀ █    ██  ██▓    \n");
	usleep(roundsleep);
	printf("    ▒██    ▒  ██▄█▒  ██  ▓██▒▓██▒    \n");
	usleep(roundsleep);
	printf("    ░ ▓██▄   ▓███▄░ ▓██  ▒██░▒██░    \n");
	usleep(roundsleep);
	printf("      ▒   ██▒▓██ █▄ ▓▓█  ░██░▒██░    \n");
	usleep(roundsleep);
	printf("    ▒██████▒▒▒██▒ █▄▒▒█████▓ ░██████▒\n");
	usleep(roundsleep);
	printf("    ▒ ▒▓▒ ▒ ░▒ ▒▒ ▓▒░▒▓▒ ▒ ▒ ░ ▒░▓  ░\n");
	usleep(roundsleep);
	printf("    ░ ░▒  ░ ░░ ░▒ ▒░░░▒░ ░ ░ ░ ░ ▒  ░\n");
	usleep(roundsleep);
	printf("    ░  ░  ░  ░ ░░ ░  ░░░ ░ ░   ░ ░   \n");
	usleep(roundsleep);
	printf("          ░  ░  ░      ░         ░  ░\n");
	usleep(finalsleep);
	printf("\n");

}

void display_art(){
	print_art(25000, 800000);
}

void display_art_nosleep(){
	print_art(0,0);	
}
