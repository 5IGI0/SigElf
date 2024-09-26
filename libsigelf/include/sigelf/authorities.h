#ifndef LIBSIGELF_AUTHORITIES_H__
#define LIBSIGELF_AUTHORITIES_H__

#ifdef LIBSIGNELF_INTERNAL
#include <openssl/x509.h>

typedef struct {
    X509_STORE *store;
} sigelf_ca_store_t;
#else
typedef void sigelf_ca_store_t;
#endif

sigelf_ca_store_t *SigElf_CAStoreNew();
int SigElf_CAStoreAddAuthorityFromFile(sigelf_ca_store_t *store, const char *path);
sigelf_ca_store_t *SigElf_GetDefaultCAStore();
int SigElf_LoadSystemCAs(sigelf_ca_store_t *store);
int SigElf_CAStoreAddDirectoryStore(sigelf_ca_store_t *store, const char *path);

#endif