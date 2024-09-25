#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <elf.h>
#include <openssl/err.h>

#include <openssl/evp.h>
#include <openssl/types.h>
#include <openssl/pem.h>

#define LIBSIGNELF_INTERNAL
#include <sigelf/defines.h>
#include <sigelf/errors.h>
#include <sigelf/signature.h>

/* TODO: handle non-host endianness */

#include "../defines.h"
#include "../macros.h"

#ifdef ELF64
#define ElfN(x) Elf64_##x
#define VERIFY_FUNC_NAME H(verify_elf64)
#elif ELF32
#define ElfN(x) Elf32_##x
#define VERIFY_FUNC_NAME H(verify_elf32)
#else
#error no ELF format provided
#endif

sigelf_signature_t *VERIFY_FUNC_NAME(unsigned const char *elf, size_t elflen) {
    /* TODO: check if a signature is present / magic numbers */
    /* TODO: the code assumes header->e_phentsize == sizeof(ElfN(Phdr)) */
    sigelf_signature_t  ret = {0};
    EVP_MD_CTX  *md_ctx = NULL;
    BIO         *bio    = NULL;
    int         success = 0;

    ElfN(Ehdr) *header      = (ElfN(Ehdr) *)elf;
    ElfN(Phdr) *pheaders    = (ElfN(Phdr) *)(elf+header->e_phoff);
    const EVP_MD *md        = EVP_sha256();

    if (md == NULL)
        CRYPT_ERR_HELP();

    OPENSSL_init();
    OpenSSL_add_all_algorithms();

    /* fetch every notes related to sigelf */
    for (size_t i = 0; i < header->e_phnum; i++) {
        if (pheaders[i].p_type == PT_NOTE) {
            ElfN(Nhdr) *note = (ElfN(Nhdr) *)(elf + pheaders[i].p_offset);
            if (note->n_namesz == sizeof(SIGELF_NOTE_NAMESPACE) && strcmp(SIGELF_NOTE_NAMESPACE, (const char *)(note+1)) == 0) {
                if (note->n_type < SIGELF_NOTE_COUNT) {
                    ret.properties[note->n_type].addr = ((unsigned const char *)note)+(sizeof(*note))+note->n_namesz;
                    ret.properties[note->n_type].len = note->n_descsz;
                }
            }
        }
    }

    if ( /* unsigned */
        ret.properties[SIGELF_SIG_NOTE].addr == NULL ||
        ret.properties[SIGELF_CERT_NOTE].addr == NULL
    ) {
        H(set_error)("no signature", SIGELF_ERR_NO_SIG);
        goto func_end;
    }

    /* get public key from the certificate */
    if (!(bio = BIO_new_mem_buf(
        ret.properties[SIGELF_CERT_NOTE].addr,
        ret.properties[SIGELF_CERT_NOTE].len-1))) CRYPT_ERR_HELP();
    
    if (!(ret.cert = PEM_read_bio_X509(bio, NULL, 0, NULL)))
        CRYPT_ERR_HELP();

    if (!(ret.pkey = X509_get_pubkey(ret.cert)))
        CRYPT_ERR_HELP();

    if (!(md_ctx = EVP_MD_CTX_create())) 
        CRYPT_ERR_HELP();
    
    if (EVP_DigestInit(md_ctx, md) != 1)
        CRYPT_ERR_HELP();

    if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, ret.pkey) != 1)
        CRYPT_ERR_HELP();

    /* hash before signature */
    if (EVP_DigestVerifyUpdate(md_ctx, elf, ret.properties[SIGELF_SIG_NOTE].addr - elf) != 1)
        CRYPT_ERR_HELP();

    /* hash after signature */
    const unsigned char *sig_end = ret.properties[SIGELF_SIG_NOTE].addr +
            ret.properties[SIGELF_SIG_NOTE].len;
    if (EVP_DigestVerifyUpdate(md_ctx, sig_end, elflen - (sig_end - elf)) != 1)
        CRYPT_ERR_HELP();

    success = 1;
    ret.has_valid_sig = 1;
    if (EVP_DigestVerifyFinal(
        md_ctx,
        ret.properties[SIGELF_SIG_NOTE].addr+ sizeof(uint32_t),
        *(uint32_t*)ret.properties[SIGELF_SIG_NOTE].addr) != 1
    ) {
        ret.has_valid_sig = 0;
        ret.bad_sig_reason = ERR_reason_error_string(ERR_get_error());
    }

    func_end:

    EVP_MD_CTX_destroy(md_ctx);
    BIO_free(bio);

    if (success) {
        sigelf_signature_t *sig = malloc(sizeof(ret));

        /* TODO: free ret */
        if (!sig) return NULL;

        return memcpy(sig, &ret, sizeof(ret));
    } else
        return NULL; /* TODO: free ret */
}