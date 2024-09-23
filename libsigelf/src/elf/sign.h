#ifndef ELF_SIGN_H
#define ELF_SIGN_H

#define LIBSIGELF_INTERNAL
#include <sigelf/signing.h>

#include "../defines.h"

unsigned char *H(sign_elf64)(
    sigelf_signer_t const *signer,
    sigelf_sign_opt_t *opt,
    unsigned char const *elf,
    size_t elflen, size_t *outlen);
unsigned char *H(sign_elf32)(
    sigelf_signer_t const *signer,
    sigelf_sign_opt_t *opt,
    unsigned char const *elf,
    size_t elflen, size_t *outlen);

#endif