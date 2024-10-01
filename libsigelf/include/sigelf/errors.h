#ifndef LIBSIGNELF_ERRORS_H__
#define LIBSIGNELF_ERRORS_H__

#define SIGELF_ERR_SUCCESS  0
#define SIGELF_ERR_CRYPTO   1
#define SIGELF_ERR_NO_SIG   2
#define SIGELF_ERR_UNKOPT   3

int         SigElf_GetErrorCode(void);
const char  *SigElf_GetErrorMessage(void);

#endif /* LIBSIGNELF_ERRORS_H__ */