#ifndef LIBSIGNELF_VERIFY_H__
#define LIBSIGNELF_VERIFY_H__

#include <stddef.h>

#include "authorities.h"

#ifdef LIBSIGNELF_INTERNAL

#include "defines.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

typedef struct {
    X509        *cert;
    EVP_PKEY    *pkey;

    struct {
        unsigned const char *addr;
        size_t len;
    } properties[SIGELF_NOTE_COUNT];

    const char *bad_sig_reason;
    unsigned int
        has_valid_sig : 1;
} sigelf_signature_t;
#else
typedef void sigelf_signature_t;
#endif /* LIBSIGNELF_INTERNAL */

sigelf_signature_t *SigElf_GetElfSignature(unsigned const char *elf, size_t elflen);

int         SigElf_IsModified(sigelf_signature_t *sig);
const char  *SigElf_GetSignerName(sigelf_signature_t *sig);
const char  *SigElf_GetIssuerName(sigelf_signature_t *sig);
int         SigElf_IsSignerTrusted(sigelf_signature_t *sig, sigelf_ca_store_t *store);
const char  *SigElf_GetRawCertificate(sigelf_signature_t *sig);
void        SigElf_FreeSignature(sigelf_signature_t *sig);

#endif /* LIBSIGNELF_VERIFY_H__ */