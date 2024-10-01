#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <sigelf/defines.h>
#include <sigelf/signing.h>
#include <sigelf/errors.h>

#include "utils.h"
#include "sign_opts.h"

int sign(int argc, char * const *argv) {
    int arg_ind = 0;
    sigelf_sign_opt_t *sign_opt = NULL;
    sign_opt_t opts = parse_sign_args(argc, argv, &arg_ind);

    sigelf_signer_t *signer = SigElf_LoadKeyFromFile(opts.key_path, opts.cert_path);
    if (signer == NULL)
        return fprintf(stderr, "unable to load key/cert: %s\n", SigElf_GetErrorMessage()), 1;

    if (opts.manifest || opts.program_id) {
        if ((sign_opt = SigElf_NewSigningOption()) == NULL)
            return fprintf(stderr, "SigElf_NewSigningOption: %s\n", SigElf_GetErrorMessage()), 1;

        if (opts.manifest)
            SigElf_AddSigningOption(SIGELF_SIGN_OPT_MANIFEST, sign_opt, opts.manifest, strlen(opts.manifest)+1);
        if (opts.program_id)
            SigElf_AddSigningOption(SIGELF_SIGN_OPT_PROGRAM_ID, sign_opt, opts.program_id, strlen(opts.program_id)+1);
    }

    size_t elflen;
    void *elf_addr = map_file_to_memory(argv[arg_ind], &elflen);
    if (elf_addr == NULL) {
        return perror(argv[arg_ind]), 1;
    }

    size_t outlen;
    void * ret = SigElf_SignElf(signer, sign_opt, elf_addr, elflen, &outlen);

    FILE *fp = fopen(argv[arg_ind+1], "wb");
    fwrite(ret, 1, outlen, fp);
    fclose(fp);

    return 0;
}