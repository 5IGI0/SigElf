#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define POSIXLY_CORRECT
#include <getopt.h>

#include <linux/limits.h>

#include "lookup_opts.h"

static void print_usage(char * const *argv) {
    printf("Usage: %s lookup <INPUT_FILE>\n", argv[0]);
    exit(1);
}

lookup_opt_t parse_lookup_args(int argc, char * const *argv, int *args_ind) {
    int opt_id = 0;
    struct option options[] = {
        {"authorities-directory", required_argument, 0, 'd'},
        {"no-default-authorities", no_argument, 0, 'n'}};
    optind = 2;
    lookup_opt_t opts = {0};
    opts.default_CAs = 1;

    while (1) {
        char c = getopt_long(argc, argv, "nd:",
            options, &opt_id);

        if (c == -1)
            break;

        switch (c) {
            case 'n':
                opts.default_CAs = 0;
                break;
            case 'd':
                opts.CAdir = optarg;
                break;
        }
    }

    if ((argc - optind) < 1)
        print_usage(argv);

    *args_ind = optind;

    return opts;
}