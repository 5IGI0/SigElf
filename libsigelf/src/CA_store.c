#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define LIBSIGNELF_INTERNAL
#include <sigelf/authorities.h>

#include "macros.h"

sigelf_ca_store_t *SigElf_CAStoreNew() {
    sigelf_ca_store_t ret = {0};
    int success = 0;

    if ((ret.store = X509_STORE_new()) == NULL)
        CRYPT_ERR_HELP();
    success = 1;

    func_end:

    if (success) {
        sigelf_ca_store_t *ret_ptr = malloc(sizeof(ret));

        if (ret_ptr) {
            memcpy(ret_ptr, &ret, sizeof(ret));
        } /* TODO: free ret on fail */
        return ret_ptr;
    } else 
        return NULL; /* TODO: free ret */
}

int SigElf_CAStoreAddAuthorityFromFile(sigelf_ca_store_t *store, const char *path) {
    BIO     *ca_bio     = NULL;
    X509    *cert       = NULL;
    int     success     = 0;

    if ((ca_bio = BIO_new_file(path, "r")) == NULL)
        CRYPT_ERR_HELP();

    if (PEM_read_bio_X509(ca_bio, &cert, NULL, NULL) == NULL)
        CRYPT_ERR_HELP();
    
    if (X509_STORE_add_cert(store->store, cert) != 1)
        CRYPT_ERR_HELP();

    success = 1;

    func_end:

    BIO_free(ca_bio);
    X509_free(cert);

    return (success == 1) ? 0 : -1;
}

sigelf_ca_store_t *SigElf_GetDefaultCAStore() {
    static sigelf_ca_store_t store;

    if (store.store != NULL)
        return &store;

    int success = 0;
    if ((store.store = X509_STORE_new()) == NULL)
        CRYPT_ERR_HELP();
    success = 1;

    func_end:

    return (success) ? &store : NULL;
}

int SigElf_CAStoreAddDirectoryStore(sigelf_ca_store_t *store, const char *path) {
    int success = 0;

    if (X509_STORE_load_locations(store->store, NULL, path) != 1)
        CRYPT_ERR_HELP();
    success = 1;

    func_end:
    
    return (success) ? 0 : -1;
}

int SigElf_LoadSystemCAs(sigelf_ca_store_t *store) {
    return SigElf_CAStoreAddDirectoryStore(store, "/etc/sigelf/certs/");
}

int H(is_certificate_trusted)(sigelf_ca_store_t *store, X509 *cert) {
    X509_STORE_CTX *ctx = NULL;
    int success         = 0;

    if ((ctx = X509_STORE_CTX_new()) == NULL)
        CRYPT_ERR_HELP();

    if (X509_STORE_CTX_init(ctx, store->store, cert, NULL) != 1)
        CRYPT_ERR_HELP();

    if (X509_STORE_CTX_verify(ctx) != 1)
        CRYPT_ERR_HELP();

    success = 1;

    func_end:

    X509_STORE_CTX_free(ctx);

    return success;
}