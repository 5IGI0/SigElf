#ifndef CA_STORE_H
#define CA_STORE_H

#include <openssl/x509.h>

#define LIBSIGNELF_INTERNAL
#include <sigelf/authorities.h>

#include "defines.h"

int H(is_certificate_trusted)(sigelf_ca_store_t *store, X509 *cert);

#endif /* CA_STORE_H */