#ifndef MACROS_H
#define MACROS_H

#include "errors.h" /* IWYU pragma: keep */

#define ERR_HELP(error_str, error_code) do {H(save_error)();           goto fund_end;} while(0)
#define CRYPT_ERR_HELP()                do {H(save_crypto_error)();    goto func_end;} while(0)
#define LIBC_ERR_HELP()                 do {H(save_libc_error)();      goto func_end;} while(0)

#endif /* MACROS_H */