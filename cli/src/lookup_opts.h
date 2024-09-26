#ifndef LOOKUP_OPT_H
#define LOOKUP_OPT_H

typedef struct {
    char    *CAdir;
    int     default_CAs;
} lookup_opt_t;

lookup_opt_t parse_lookup_args(int argc, char * const *argv, int *args_ind);

#endif /* LOOKUP_OPT_H */