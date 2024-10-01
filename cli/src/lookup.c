#include <stdio.h>
#include <stddef.h>

#include <sigelf/authorities.h>
#include <sigelf/signature.h>
#include <sigelf/errors.h>

#include "utils.h"
#include "lookup_opts.h"

int lookup(int argc, char * const *argv) {
    int arg_ind;
    size_t elflen;
    lookup_opt_t args = parse_lookup_args(argc, argv, &arg_ind);

    void *elf_addr = map_file_to_memory(argv[arg_ind], &elflen);
    if (elf_addr == NULL)
        return perror(argv[2]), 1;

    if (args.default_CAs) {
        if (SigElf_LoadSystemCAs(SigElf_GetDefaultCAStore()) < 0)
            fprintf(stderr, "Warning: unable to load default CAs: %s\n", SigElf_GetErrorMessage());
    }

    if (args.CAdir) {
        if (SigElf_CAStoreAddDirectoryStore(SigElf_GetDefaultCAStore(), args.CAdir) < 0)
            fprintf(stderr, "Warning: unable to load CA directory: %s\n", SigElf_GetErrorMessage());
    }

    sigelf_signature_t *sig = SigElf_GetElfSignature(elf_addr, elflen);
    if (sig == NULL) {
        return fprintf(stderr, "%s: %s\n", argv[arg_ind], SigElf_GetErrorMessage()), 1; 
    }

    printf(
        "Signed By : %s\n"
        "Issued By : %s\n"
        "Trusted   : %s\n"
        "Status    : %s\n",
        SigElf_GetSignerName(sig),
        SigElf_GetIssuerName(sig),
        SigElf_IsSignerTrusted(sig, NULL) ? "\e[92mYes\e[0m" : "\e[91mNo\e[0m",
        SigElf_IsModified(sig) ? "\e[91mModified\e[0m" : "\e[92mUnaltered\e[0m");

    const char *tmp;

    if ((tmp = SigElf_GetProgramId(sig)))
        printf("Program ID: %s\n", tmp);

    if ((tmp = SigElf_GetManifest(sig)))
        printf("Manifest  : %s\n", tmp);

    return 0;
}