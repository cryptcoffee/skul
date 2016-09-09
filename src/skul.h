#ifndef __SKUL_H__
#define __SKUL_H__

#include "../lib/skulfs.h"
#include "../lib/config.h"
#include "../lib/luks.h"

/* for testing purposes only 
 * #define TESTING 
 * */ 

#define SKUL_MAJOR 0
#define SKUL_MINOR 2
/* Comment SKUL_FIX if there is no
 * hotfix in this version */
#define SKUL_FIX 1

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
	int (*clean)();
	int (*cpytarget_ctx)();
	int (*open_key)();
	usrp UP;
	int attack_mode;
	char *pwlist_path;
	char *path;					/* path of the encrypted target */
	int fast;					/* maybe put it in the luks_ctx? */
	int num_pwds;
	int cur_pwd;

	LUKS_CTX *luks;
	/* other contexts goes here */

}SKUL_CTX;

int SKUL_CTX_cpy(SKUL_CTX *dst, SKUL_CTX *src);


/* Functions for LUKS */
int LUKS_init(SKUL_CTX *ctx);
int LUKS_clean(SKUL_CTX *ctx);
int LUKS_CTXcpy(SKUL_CTX *dest, SKUL_CTX *surc);


#endif
