#include <stdio.h>
#include <stddef.h>

#include <sigelf/authorities.h>
#include <sigelf/signature.h>
#include <sigelf/errors.h>

#include "utils.h"

int lookup(int argc, char * const *argv) {
    size_t elflen;
    void *elf_addr = map_file_to_memory(argv[2], &elflen);
    
    if (elf_addr)
        return perror(argv[2]), 1;

    if (SigElf_LoadSystemCAs(SigElf_GetDefaultCAStore()) < 0)
        fprintf(stderr, "Warning: unable to load default CAs: %s\n", SigElf_GetErrorMessage());

    sigelf_signature_t *sig = SigElf_GetElfSignature(elf_addr, elflen);

    if (sig == NULL) {
        return fprintf(stderr, "%s: %s\n", argv[2], SigElf_GetErrorMessage()), 1; 
    }

    printf(
        "Signed By: %s\n"
        "Issued By: %s\n"
        "Trusted  : %s\n"
        "Status   : %s\n",
        SigElf_GetSignerName(sig),
        SigElf_GetIssuerName(sig),
        SigElf_IsSignerTrusted(sig, NULL) ? "\e[92mYes\e[0m" : "\e[91mNo\e[0m",
        SigElf_IsModified(sig) ? "\e[91mModified\e[0m" : "\e[92mUnaltered\e[0m");
    return 0;
}