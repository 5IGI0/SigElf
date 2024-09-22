#ifndef ERRORS_H
#define ERRORS_H

#include "defines.h"

void H(set_error)(char *str, int code);
void H(save_crypto_error)(void);
void H(save_libc_error)(void);

#endif