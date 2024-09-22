#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#include <sigelf/signing.h>

#include "utils.h"
#include "constants.h"

int sign(int argc, char const **argv) {
    assert(argc == 4);

    sigelf_signer_t *signer = SigElf_LoadKeyFromFile(DEFAULT_PKEY_PATH, DEFAULT_CERT_PATH);
    assert(signer);

    size_t elflen;
    void *elf_addr = map_file_to_memory(argv[2], &elflen);

    size_t outlen;
    void * ret = SigElf_SignElf(signer, NULL, elf_addr, elflen, &outlen);

    FILE *fp = fopen(argv[3], "wb");
    fwrite(ret, 1, outlen, fp);
    fclose(fp);

    return 0;
}