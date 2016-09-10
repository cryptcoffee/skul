#ifndef __SKUL_H__
#define __SKUL_H__

#include <stdint.h>
#include "../lib/config.h"
#include "../lib/luks/luks.h"

/* for testing purposes only 
 * #define TESTING 
 * */ 

#define SKUL_MAJOR 0
#define SKUL_MINOR 3
#define SKUL_FIX 0

/* debug and warnings
 * #define DEBUG 
 * #define WARN 
 * */
#define LOG 0

typedef enum {
	LUKS
	/* other targets goes here*/
}target_t;

typedef struct skul_ctx{
	
	target_t target;
	int (*init)();
	void (*clean_target_ctx)();
	int (*cpy_target_ctx)();
	int (*open_key)();
	usrp UP;
	int attack_mode;
	char *pwlist_path;
	char *path;					/* path of the encrypted target */
	int fast;					/* maybe put it in the luks_ctx? */

	/* multiple password management */
	int pwd_default;
	int num_pwds;
	int cur_pwd;
	int *pwd_ord;

	LUKS_CTX *luks;
	/* other contexts goes here */

}SKUL_CTX;

void SKUL_CTX_init(SKUL_CTX *ctx);
int SKUL_CTX_cpy(SKUL_CTX *dst, SKUL_CTX *src);


/* Functions for LUKS */
int LUKS_init(SKUL_CTX *ctx);
void LUKS_clean(SKUL_CTX *ctx);
int LUKS_CTXcpy(SKUL_CTX *dest, SKUL_CTX *surc);


#endif
