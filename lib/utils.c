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
