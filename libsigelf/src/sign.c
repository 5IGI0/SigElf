#include <stdio.h>
#include <assert.h>

#include <elf.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdlib.h>

#define LIBSIGNELF_INTERNAL
#include <sigelf/signing.h>

#include "elf/sign.h" /* IWYU pragma: keep (???) */
#include "macros.h"

sigelf_signer_t *SigElf_LoadKeyFromFile(char const *key_path, char const *cert_path) {
    sigelf_signer_t ret = {0};
    int success = 0;
    FILE *fp = NULL;

    /* loading private key */
    if ((fp = fopen(key_path, "rb")) == NULL)
        LIBC_ERR_HELP();
    
    if ((ret.pkey = EVP_PKEY_new()) == NULL)
        CRYPT_ERR_HELP();

    if (PEM_read_PrivateKey(fp, &ret.pkey, NULL, NULL) == NULL)
        CRYPT_ERR_HELP();

    fclose(fp);
    fp = NULL;

    /* TODO: check certificate validity */
    if ((fp = fopen(cert_path, "rb")) == NULL)
        LIBC_ERR_HELP();

    if (fseek(fp, 0, SEEK_END) < 0)
        LIBC_ERR_HELP();

    long certlen = 0;
    if ((certlen = ftell(fp)) < 0)
        LIBC_ERR_HELP();
    ret.certlen = certlen;

    if (fseek(fp, 0, SEEK_SET) < 0)
        LIBC_ERR_HELP();

    if ((ret.cert = malloc(ret.certlen + 1)) == NULL)
        LIBC_ERR_HELP();

    assert(fread(ret.cert, 1, ret.certlen, fp) == ret.certlen);
    ret.cert[ret.certlen] = 0;
    fclose(fp);
    fp = NULL;
    success = 1;

    func_end:

    if (fp) fclose(fp);

    if (success) {
        sigelf_signer_t *ret_ptr = malloc(sizeof(ret));
        if (ret_ptr) 
            return memcpy(ret_ptr, &ret, sizeof(ret));
        H(save_libc_error)();
    }

    EVP_PKEY_free(ret.pkey);
    return NULL;
}

unsigned char *SigElf_SignElf(
    sigelf_signer_t const *signer,
    sigelf_sign_opt_t *opt,
    unsigned char const *elf,
    size_t elflen, size_t *outlen) {
    if (elf[EI_CLASS] == ELFCLASS64)
        return H(sign_elf64)(signer, opt, elf, elflen, outlen);
    return H(sign_elf32)(signer, opt, elf, elflen, outlen);
}
