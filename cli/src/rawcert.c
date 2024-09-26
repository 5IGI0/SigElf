#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <sigelf/authorities.h>
#include <sigelf/signature.h>
#include <sigelf/errors.h>

#include "utils.h"

int rawcert(int argc, char * const *argv) {
    size_t elflen;

    if (argc < 3) {
        printf("Usage: %s rawcert <INPUT_FILE>\n", argv[0]);
        exit(1);
    }

    void *elf_addr = map_file_to_memory(argv[2], &elflen);
    if (elf_addr == NULL)
        return perror(argv[2]), 1;

    sigelf_signature_t *sig = SigElf_GetElfSignature(elf_addr, elflen);


    if (sig == NULL) {
        return fprintf(stderr, "%s: %s\n", argv[2], SigElf_GetErrorMessage()), 1; 
    }

    fputs(SigElf_GetRawCertificate(sig), stdout);

    return 0;
}