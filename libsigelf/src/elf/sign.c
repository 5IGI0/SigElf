#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <elf.h>
#include <openssl/err.h>

#include <openssl/evp.h>
#include <openssl/types.h>

#define LIBSIGNELF_INTERNAL
#include <sigelf/defines.h>
#include <sigelf/signing.h>

#include "../defines.h"
#include "../macros.h"

/* TODO: handle non-host endianness */

#ifdef ELF64
#define ElfN(x) Elf64_##x
#define SIGNING_FUNC_NAME H(sign_elf64)
#elif ELF32
#define ElfN(x) Elf32_##x
#define SIGNING_FUNC_NAME H(sign_elf32)
#else
#error no ELF format provided
#endif

struct elf_note {
    const unsigned char  *addr; /* NULL = will be filled with 0 */
    size_t      len;
};
static void set_extra_notes(struct elf_note notes[SIGELF_NOTE_COUNT], sigelf_sign_opt_t *opt) {
    if (opt == NULL) return;
    for (size_t i = 0; i < SIGELF_NOTE_COUNT; i++) {
        if (opt->properties[i].len) {
            notes[i].addr = opt->properties[i].addr;
            notes[i].len = opt->properties[i].len;
        }
    }
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

static ElfN(Addr) get_next_aligned_vaddr(ElfN(Phdr) *phdr, size_t phnum) {
    ElfN(Addr) phdr_vaddr = 0;
    for (size_t i = 0; i < phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            ElfN(Addr) end_of_segment = phdr[i].p_vaddr + phdr[i].p_memsz;
            if (phdr_vaddr < end_of_segment)
                phdr_vaddr = end_of_segment;
        }
    }
    return (phdr_vaddr|0xFFF)+1;
}

unsigned char *SIGNING_FUNC_NAME(
    sigelf_signer_t const *signer,
    sigelf_sign_opt_t *opt,
    unsigned char const *elf,
    size_t elflen, size_t *outlen) {
    /* TODO: the code assumes header->e_phentsize == sizeof(ElfN(Phdr)) */
    struct elf_note notes[SIGELF_NOTE_COUNT] = {0};
    unsigned char   *retbuf    = NULL;
    size_t          siglen     = 0;
    int             success    = 0;

    size_t round_elflen     = (elflen|0xFFF)+1;
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
    notes[SIGELF_SIG_NOTE].addr     = NULL;
    notes[SIGELF_SIG_NOTE].len      = siglen + sizeof(uint32_t);
    notes[SIGELF_CERT_NOTE].addr    = (const unsigned char *)signer->cert;
    notes[SIGELF_CERT_NOTE].len     = signer->certlen+1; // cert + nullbyte
    notes[SIGELF_VER_NOTE].addr     = (const unsigned char *)"0.1.0";
    notes[SIGELF_VER_NOTE].len      = sizeof("0.1.0");

    *outlen = round_elflen;
    /* new program headers */
    *outlen += (
        header->e_phentsize *
        (header->e_phnum+count_notes(notes)+1));
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
    memcpy(retbuf+round_elflen, retbuf+header->e_phoff, header->e_phentsize * header->e_phnum);
    header->e_phoff = round_elflen;

    /* add new program headers */
    ElfN(Off) sig_start = 0;
    ElfN(Off) sig_end   = 0;
    ElfN(Off) content_offset = (
            round_elflen +
            (header->e_phentsize * (
                header->e_phnum + count_notes(notes) + 1)));
    for (size_t i = 0; i < SIGELF_NOTE_COUNT; i++) {
        if (notes[i].len == 0)
            continue;

        /* program header */
        ElfN(Phdr) *phdr    = (ElfN(Phdr) *)(retbuf + header->e_phoff + (header->e_phentsize * header->e_phnum));
        phdr->p_type        = PT_NOTE;
        phdr->p_filesz      = notes[i].len + sizeof(ElfN(Nhdr)) + sizeof(SIGELF_NOTE_NAMESPACE);
        phdr->p_memsz       = notes[i].len + sizeof(ElfN(Nhdr)) + sizeof(SIGELF_NOTE_NAMESPACE);
        phdr->p_offset      = content_offset;
        phdr->p_vaddr       = content_offset;
        phdr->p_paddr       = content_offset;
        phdr->p_flags       = PF_R;
        phdr->p_align       = 1;
        header->e_phnum++;
        content_offset += phdr->p_filesz;

        /* note header */
        ElfN(Nhdr) *nhdr    = (ElfN(Nhdr) *)(retbuf + phdr->p_offset);
        nhdr->n_namesz      = sizeof(SIGELF_NOTE_NAMESPACE);
        nhdr->n_descsz      = notes[i].len;
        nhdr->n_type        = i;

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

    /* add the new phdr into a loadable segment */
    ElfN(Phdr) *phdr_seg = (ElfN(Phdr) *)(retbuf + header->e_phoff + (header->e_phentsize * header->e_phnum));
    phdr_seg->p_type = PT_LOAD;
    phdr_seg->p_filesz = content_offset - round_elflen;
    phdr_seg->p_memsz =  content_offset - round_elflen;
    phdr_seg->p_offset = round_elflen;
    phdr_seg->p_vaddr = get_next_aligned_vaddr((ElfN(Phdr) *)(retbuf + header->e_phoff), header->e_phnum);
    phdr_seg->p_flags = PF_R|PF_W;
    phdr_seg->p_align = 0x1000;
    header->e_phnum++;

    /* patch phdr program header */
    for (size_t i = 0; i < header->e_phnum; i++) {
        ElfN(Phdr) *phdr = (void *)(retbuf + header->e_phoff);
        if (phdr->p_type == PT_PHDR) {
            phdr->p_offset  = header->e_phoff;
            // phdr->p_paddr   = header->e_phoff;
            phdr->p_vaddr   = phdr_seg->p_vaddr;
            phdr->p_filesz  = content_offset - round_elflen;
            phdr->p_memsz   = content_offset - round_elflen;          
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