#ifndef SIGN_OPT_H
#define SIGN_OPT_H

typedef struct {
    char *profile;
    char *cert_path;
    char *key_path;

    char *input_file;
    char *output_file;
} sign_opt_t;

sign_opt_t parse_sign_args(int argc, char * const *argv, int *args_ind);

#endif /* SIGN_OPT_H */