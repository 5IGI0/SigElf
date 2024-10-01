#include "sigelf/defines.h"
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define LIBSIGNELF_INTERNAL
#include <sigelf/signature.h>
#include <sigelf/authorities.h>

#include "defines.h"
#include "CA_store.h"

int SigElf_IsModified(sigelf_signature_t *sig) {
    return (sig) ? (!sig->has_valid_sig) : 1;
}

static const char *attr_from_x509_name(X509_NAME *name, int attr) {
    int num_entries = X509_NAME_entry_count(name);
    for (int i = 0; i < num_entries; i++) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
        if (!entry) break;

        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
        if (OBJ_obj2nid(obj) == attr) {
            return (char *)X509_NAME_ENTRY_get_data(entry)->data;
        }
    }

    return "<no value>";
}

const char *SigElf_GetSignerName(sigelf_signature_t *sig) {
    if (!sig) return "<no signature>";

    X509_NAME *name;

    if ((name = X509_get_subject_name(sig->cert)) == NULL)
        return "<error>";

    return attr_from_x509_name(name, NID_commonName);
}

const char *SigElf_GetIssuerName(sigelf_signature_t *sig) {
    if (!sig) return "<no signature>";

    X509_NAME *name;

    if ((name = X509_get_issuer_name(sig->cert)) == NULL)
        return "<error>";

    return attr_from_x509_name(name, NID_commonName);
}

int SigElf_IsSignerTrusted(sigelf_signature_t *sig, sigelf_ca_store_t *store) {
    if (store == NULL)
        store = SigElf_GetDefaultCAStore();

    return H(is_certificate_trusted)(store, sig->cert);
}

unsigned const char *SigElf_GetSignatureProperty(sigelf_signature_t *sig, int property_id, size_t *proplen) {
    if (sig == NULL || property_id >= SIGELF_NOTE_COUNT)
        return NULL;

    if (proplen)
        *proplen = sig->properties[property_id].len;

    return sig->properties[property_id].addr;
}

const char *SigElf_GetRawCertificate(sigelf_signature_t *sig) {
    // TODO: check for nullbyte
    return (const char *)SigElf_GetSignatureProperty(sig, SIGELF_CERT_NOTE, NULL);
}

const char *SigElf_GetProgramId(sigelf_signature_t *sig) {
    // TODO: check for nullbyte
    return (const char *)SigElf_GetSignatureProperty(sig, SIGELF_PROGRAM_ID_NOTE, NULL);
}

const char *SigElf_GetManifest(sigelf_signature_t *sig) {
    // TODO: check for nullbyte
    return (const char *)SigElf_GetSignatureProperty(sig, SIGELF_MANIFEST_NOTE, NULL);
}

void H(free_signature)(sigelf_signature_t sig) {
    X509_free(sig.cert);
    EVP_PKEY_free(sig.pkey);
}

void SigElf_FreeSignature(sigelf_signature_t *sig) {
    if (sig == NULL) return;
    H(free_signature)(*sig);
    free(sig);
}