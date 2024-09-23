#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#include <sigelf/signing.h>

#include "utils.h"
#include "sign_opts.h"

int sign(int argc, char * const *argv) {
    int arg_ind = 0;
    sign_opt_t opts = parse_sign_args(argc, argv, &arg_ind);

    sigelf_signer_t *signer = SigElf_LoadKeyFromFile(opts.key_path, opts.cert_path);
    assert(signer);

    size_t elflen;
    void *elf_addr = map_file_to_memory(argv[arg_ind], &elflen);

    size_t outlen;
    void * ret = SigElf_SignElf(signer, NULL, elf_addr, elflen, &outlen);

    FILE *fp = fopen(argv[arg_ind+1], "wb");
    fwrite(ret, 1, outlen, fp);
    fclose(fp);

    return 0;
}