#include <string.h>
#include <errno.h>

#include <openssl/err.h>

#include <sigelf/errors.h>
#include <string.h>
#include "defines.h"

static int error_code = 0;
static char static_error_buff[256] = "";
static const char *error_str = "Success";

void H(set_error)(char *str, int code) {
    error_str = str;
    error_code = code;
}

void H(save_crypto_error)(void) {
    int err = ERR_get_error();
    ERR_error_string_n(err, static_error_buff, sizeof(static_error_buff)-1);
    H(set_error)(static_error_buff, SIGELF_ERR_CRYPTO);
}

void H(save_libc_error)(void) {
    H(set_error)(strerror(errno), errno);
}

int SigElf_GetErrorCode(void) {
    return error_code;
}

const char *SigElf_GetErrorMessage(void) {
    return error_str;
}