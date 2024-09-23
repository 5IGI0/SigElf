#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define POSIXLY_CORRECT
#include <getopt.h>

#include <linux/limits.h>

#include "sign_opts.h"

static void print_usage(char * const *argv) {
    printf("%s sign <INPUT_FILE> <OUTPUT_FILE>\n", argv[0]);
    exit(1);
}

sign_opt_t parse_sign_args(int argc, char * const *argv, int *args_ind) {
    int opt_id = 0;
    struct option options[] = {
        {"private-key", required_argument, 0, 'k'},
        {"certificate", required_argument, 0, 'c'},
        {"profile", required_argument, 0, 'p'}
    };
    optind = 2;
    sign_opt_t opts = {0};

    while (1) {
        char c = getopt_long(argc, argv, "k:c:p:",
            options, &opt_id);

        if (c == -1)
            break;

        switch (c) {
            case 'p':
                opts.profile = optarg;
                break;
            case 'k':
                opts.key_path = optarg;
                break;
            case 'c':
                opts.cert_path = optarg;
                break;
        }
    }

    if (opts.cert_path || opts.key_path) {
        if (opts.key_path == NULL)
            exit((fputs("--private-key is required if using --certificate\n", stderr), 1));
        if (opts.cert_path == NULL)
            exit((fputs("--certificate is required if using --private-key\n", stderr), 1));
    } else {
        char *home;

        if (opts.profile == NULL)
            opts.profile = "default";

        assert(home = getenv("HOME"));
        assert(opts.key_path = malloc(
            strlen(home) + strlen(opts.profile) +
            sizeof("/.sigelf/.key")));
        assert(opts.cert_path = malloc(
            strlen(home) + strlen(opts.profile) +
            sizeof("/.sigelf/.crt")));
        
        opts.key_path[0] = 0;
        strcat(opts.key_path, home);
        strcat(opts.key_path, "/.sigelf/");
        strcat(opts.key_path, opts.profile);
        strcat(opts.key_path, ".key");
        opts.cert_path[0] = 0;
        strcat(opts.cert_path, home);
        strcat(opts.cert_path, "/.sigelf/");
        strcat(opts.cert_path, opts.profile);
        strcat(opts.cert_path, ".crt");
    }

    if ((argc - optind) < 2)
        print_usage(argv);

    *args_ind = optind;

    return opts;
}