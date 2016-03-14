#ifndef __ATTACKS_H__
#define __ATTACKS_H__

int bruteforce(int len, char *set, 
		int set_len, pheader *header, 
		int iv_mode, int chain_mode, lkey_t *encrypted, 
		char *crypt_disk, int keyslot, int num_thr, int fst_chk, int prg_bar);

int pwlist(pheader *header, int iv_mode, int chain_mode, 
		lkey_t *encrypted, char *crypt_disk, int keyslot, int num_thr, int fst_chk, int prg_bar);

char *init_set(int *set_len, int id_set);

#endif
