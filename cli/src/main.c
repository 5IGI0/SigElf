#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sign(int argc, char * const*argv);
int lookup(int argc, char * const*argv);
int rawcert(int argc, char * const *argv);

static void print_usage(char const *progname) {
    printf(
        "Usage: %s <sign|verify|rawcert> [OPTIONS...] <ARGS...>\n\n"
        "Examples:\n"
        "\t%s sign ./program.bin\n"
        "\t%s lookup ./program.bin\n",
        progname, progname, progname);
    exit(1);
}

int main(int argc, char * const*argv) {
    if (argc <= 2) {
        print_usage(argv[0]);
    } else if (strcmp("sign", argv[1]) == 0) {
        return sign(argc, argv);
    } else if (strcmp("lookup", argv[1]) == 0) {
        return lookup(argc, argv);
    } else if (strcmp("rawcert", argv[1]) == 0) {
        return rawcert(argc, argv);
    } else {
        print_usage(argv[0]);
    }
    return 0;
}