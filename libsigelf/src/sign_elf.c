#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <elf.h>
#include <openssl/err.h>

#include <openssl/evp.h>
#include <openssl/types.h>

#define LIBSIGNELF_INTERNAL
#include <sigelf/defines.h>
#include <sigelf/signing.h>

#include "macros.h" /* CRYPT_ERR_HELP() */

/* TODO: manage non-host endianness */

#define ELF64

#ifdef ELF64
#define ElfN(x) Elf64_##x
#endif

struct elf_note {
    const char  *addr; /* NULL = will be filled of 0*/
    size_t      len;
};
static void set_extra_notes(struct elf_note notes[SIGELF_NOTE_COUNT], sigelf_sign_opt_t *opt) {
    (void) notes;
    (void) opt;
}

static size_t count_notes(struct elf_note notes[SIGELF_NOTE_COUNT]) {
    size_t ret = 0;

    for (size_t i = 0; i < SIGELF_NOTE_COUNT; i++)
        ret += notes[i].len != 0;

    return ret;
}

static size_t notes_content_len(struct elf_note notes[SIGELF_NOTE_COUNT]) {
    size_t ret = 0;

    for (size_t i = 0; i < SIGELF_NOTE_COUNT; i++)
        ret += notes[i].len;

    return ret;
}

unsigned char *SigElf_SignElf(sigelf_signer_t const *signer, sigelf_sign_opt_t *opt, unsigned char const *elf, size_t elflen, size_t *outlen) {
    /* TODO: check if a signature is present / magic numbers */
    /* TODO: the code assumes header->e_phentsize == sizeof(ElfN(Phdr)) */
    struct elf_note notes[SIGELF_NOTE_COUNT] = {0};
    unsigned char   *retbuf    = NULL;
    size_t          siglen     = 0;
    int             success    = 0;

    ElfN(Ehdr)   *header    = (ElfN(Ehdr) *)elf;
    EVP_MD_CTX   *md_ctx    = EVP_MD_CTX_create();
    const EVP_MD *md        = EVP_sha256();

    OPENSSL_init();
    OpenSSL_add_all_algorithms();

    if (!md_ctx || !md)                     CRYPT_ERR_HELP();
    if (EVP_DigestInit(md_ctx, md) != 1)    CRYPT_ERR_HELP();
    if (EVP_DigestSignInit(md_ctx, NULL, md, NULL, signer->pkey) != 1)  CRYPT_ERR_HELP();
    if (EVP_DigestSign(md_ctx, NULL, &siglen, NULL, 0) != 1)            CRYPT_ERR_HELP();

    set_extra_notes(notes, opt);
    notes[SIGELF_SIG_NOTE].addr = NULL;
    notes[SIGELF_SIG_NOTE].len  = siglen + sizeof(uint32_t);
    notes[SIGELF_CERT_NOTE].addr = signer->cert;
    notes[SIGELF_CERT_NOTE].len  = signer->certlen+1; // cert + nullbyte

    *outlen = elflen;
    /* new program headers */
    *outlen += (
        header->e_phentsize *
        (header->e_phnum+count_notes(notes)));
    /* notes content */
    *outlen += notes_content_len(notes);
    /* note headers and namespaces */
    *outlen +=
        (sizeof(SIGELF_NOTE_NAMESPACE) + sizeof(ElfN(Nhdr))) *
        count_notes(notes);

    if (!(retbuf = calloc(1, *outlen)))
        LIBC_ERR_HELP();

    memcpy(retbuf, elf, elflen);
    header = (ElfN(Ehdr) *)retbuf;

    /* relocate program headers */
    memcpy(retbuf+elflen, retbuf+header->e_phoff, header->e_phentsize * header->e_phnum);
    header->e_phoff = elflen;

    /* add new program headers */
    ElfN(Off) sig_start = 0;
    ElfN(Off) sig_end   = 0;
    ElfN(Off) content_offset = (
            elflen +
            (header->e_phentsize * (
                header->e_phnum + count_notes(notes))));
    for (size_t i = 0; i < SIGELF_NOTE_COUNT; i++) {
        if (notes[i].len == 0)
            continue;

        /* program header */
        ElfN(Phdr) *phdr = (ElfN(Phdr) *)(retbuf + elflen + (header->e_phentsize * header->e_phnum));
        phdr->p_type = PT_NOTE;
        phdr->p_filesz = notes[i].len + sizeof(ElfN(Nhdr)) + sizeof(SIGELF_NOTE_NAMESPACE);
        phdr->p_offset = content_offset;
        header->e_phnum++;
        content_offset += phdr->p_filesz;

        /* note header */
        ElfN(Nhdr) *nhdr = (ElfN(Nhdr) *)(retbuf + phdr->p_offset);
        nhdr->n_namesz = sizeof(SIGELF_NOTE_NAMESPACE);
        nhdr->n_descsz = notes[i].len;
        nhdr->n_type = i;

        memcpy(retbuf + phdr->p_offset + sizeof(*nhdr), /* namespace */
            SIGELF_NOTE_NAMESPACE, sizeof(SIGELF_NOTE_NAMESPACE));

        if (notes[i].addr) /* content */
            memcpy(retbuf + phdr->p_offset + sizeof(*nhdr) + sizeof(SIGELF_NOTE_NAMESPACE),
                notes[i].addr, notes[i].len);

        /* save signature offset */
        if (i == SIGELF_SIG_NOTE) {
            sig_start   = phdr->p_offset + sizeof(ElfN(Nhdr)) + nhdr->n_namesz;
            sig_end     = phdr->p_offset+phdr->p_filesz;
        }

    }

    /* hash data before the signature */
    if (EVP_DigestSignUpdate(md_ctx, retbuf, sig_start) != 1)
        CRYPT_ERR_HELP();

    /* hash data after the signature */
    if (EVP_DigestSignUpdate(md_ctx, retbuf + sig_end, (*outlen) - sig_end) != 1)
        CRYPT_ERR_HELP();
    
    /* sign */
    if (EVP_DigestSignFinal(
        md_ctx,
        retbuf + sig_start + sizeof(uint32_t),
        &siglen) != 1) CRYPT_ERR_HELP();

    /* add signature length */
    *(uint32_t *)(retbuf + sig_start) = siglen;
    success = 1;

    func_end:

    EVP_MD_CTX_destroy(md_ctx);

    if (success == 0) {
        free(retbuf);
        retbuf = NULL;
    }

    return retbuf;
}