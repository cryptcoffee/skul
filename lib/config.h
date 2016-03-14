#ifndef CONFIG_H
#define CONFIG_H

typedef struct usr_preferences{
	int MIN_LEN;
	int MAX_LEN;
	int NUM_THR;
	int ALP_SET;
	int FST_CHK;
	int KEY_SEL;
	int SEL_MOD;
	int PRG_BAR;
}usrp;

int read_cfg(usrp *UP);

#endif
