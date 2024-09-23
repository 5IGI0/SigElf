#ifndef ELF_SIGN_H
#define ELF_SIGN_H

#include <stddef.h>
#include <sigelf/signature.h>
#include "../defines.h"

sigelf_signature_t *H(verify_elf64)(unsigned const char *elf, size_t elflen);
sigelf_signature_t *H(verify_elf32)(unsigned const char *elf, size_t elflen);

#endif