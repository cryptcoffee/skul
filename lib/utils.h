#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
int errprint(const char *format, ...);
int dbgprint(int debug, const char *format, ...);
uint32_t l2bEndian(uint32_t num);
void display_art();

#endif
