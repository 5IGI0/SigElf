#include <openssl/objects.h>
#include <openssl/x509.h>

#define LIBSIGNELF_INTERNAL
#include <sigelf/signature.h>

int SigElf_IsModified(sigelf_signature_t *sig) {
    return (sig) ? (!sig->has_valid_sig) : 1;
}

const char *SigElf_GetSignerName(sigelf_signature_t *sig) {
    if (!sig) return "<no signer>";

    X509_NAME *subj = X509_get_subject_name(sig->cert);

    int num_entries = X509_NAME_entry_count(subj);
    for (int i = 0; i < num_entries; i++) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subj, i);
        if (!entry) break;

        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
        if (OBJ_obj2nid(obj) == NID_commonName) {
            return (char *)X509_NAME_ENTRY_get_data(entry)->data;
        }

    }

    return "<no name>";
}