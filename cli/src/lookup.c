#include <stdio.h>
#include <stddef.h>

#include <sigelf/signature.h>
#include <sigelf/errors.h>

#include "utils.h"

int lookup(int argc, char const **argv) {
    size_t elflen;
    void *elf_addr = map_file_to_memory(argv[2], &elflen);

    sigelf_signature_t *sig = SigElf_GetElfSignature(elf_addr, elflen);

    if (sig == NULL) {
        return fprintf(stderr, "%s: %s\n", argv[2], SigElf_GetErrorMessage()), 1; 
    }

    printf(
        "Signed By: %s\n"
        "Status   : %s\n",
        SigElf_GetSignerName(sig),
        SigElf_IsModified(sig) ? "\e[91mModified\e[0m" : "\e[92mUnaltered\e[0m"
    );
}