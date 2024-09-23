#include <sigelf/signature.h>

#include <elf.h>

#include "defines.h"
#include "elf/verify.h" /* IWYU pragma: keep (???) */

sigelf_signature_t *SigElf_GetElfSignature(unsigned const char *elf, size_t elflen) {
    if (elf[EI_CLASS] == ELFCLASS64)
        return H(verify_elf64)(elf, elflen);
    return H(verify_elf32)(elf, elflen);
}