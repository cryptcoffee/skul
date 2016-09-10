/*
 * Random supply helper
 * Copyright 2004, Clemens Fruhwirth <clemens@endorphin.org>
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
 
int getRandom(char *buf, int len)
{
	int randomfd = 0; 

	/*FIXME Run a FIPS test for the random device or include
	 PRNG if urandom not avail.*/
	
	randomfd = open("/dev/urandom",O_RDONLY);
	if(-1 == randomfd) {
		perror("generate_LUKS_masterkey:"); return -1;
	}
	while(len) { 
		int r;
		r = read(randomfd,buf,len);
		if (-1 == r && errno != -EINTR) {	
			perror("read: "); return -1;
		}
		len-= r; buf += r;
	}
	close(randomfd);
	return 0;
}
