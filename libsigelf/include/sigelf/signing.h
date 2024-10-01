#ifndef LIBSIGNELF_SIGN_H__
#define LIBSIGNELF_SIGN_H__

#include <stddef.h>

#ifdef LIBSIGNELF_INTERNAL
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "defines.h"

typedef struct {
    EVP_PKEY *pkey;
    size_t certlen;
    char *cert;
} sigelf_signer_t;

/* for future use */
typedef struct {
    struct {
        unsigned const char *addr;
        size_t len;
    } properties[SIGELF_NOTE_COUNT];
} sigelf_sign_opt_t;
#else
typedef void sigelf_signer_t;
typedef void sigelf_sign_opt_t;
#endif /* LIBSIGNELF_INTERNAL */

sigelf_signer_t     *SigElf_LoadKeyFromFile(char const *key_path, char const *cert_path);
unsigned char       *SigElf_SignElf(sigelf_signer_t const *signer, sigelf_sign_opt_t *opt, unsigned char const *elf, size_t elflen, size_t *outlen);
sigelf_sign_opt_t   *SigElf_NewSigningOption();
#define SIGELF_SIGN_OPT_MANIFEST    1
#define SIGELF_SIGN_OPT_PROGRAM_ID  2
int                 SigElf_AddSigningOption(int dttyp, sigelf_sign_opt_t *opt, const void *dt, size_t dtlen);

#endif /* LIBSIGNELF_SIGN_H__ */