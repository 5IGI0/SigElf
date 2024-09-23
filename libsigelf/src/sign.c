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

sigelf_signer_t *SigElf_LoadKeyFromFile(char const *key_path, char const *cert_path) {
    sigelf_signer_t ret = {0};

    /* loading private key */
    FILE *fp = fopen(key_path, "rb");
    assert(fp);

    ret.pkey = EVP_PKEY_new();
    assert(ret.pkey);

    if (!PEM_read_PrivateKey(fp, &ret.pkey, NULL, NULL))
        return fclose(fp), NULL;
    fclose(fp);

    /* TODO: check certificate validity */
    fp = fopen(cert_path, "rb");
    fseek(fp, 0, SEEK_END);
    ret.certlen = ftell(fp);
    assert(ret.certlen > 0);
    rewind(fp);
    assert(ret.cert = malloc(ret.certlen + 1));
    assert(fread(ret.cert, 1, ret.certlen, fp) == ret.certlen);
    ret.cert[ret.certlen] = 0;
    fclose(fp);

    /* it worked so we can finally allocate it */
    sigelf_signer_t *ret_ptr = malloc(sizeof(ret));
    assert(ret_ptr);
    memcpy(ret_ptr, &ret, sizeof(ret));

    return ret_ptr;
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
