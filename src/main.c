#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#include "scanner.h"

void print_usage(const char *prog_name) {
    fprintf(stderr, "usage: sudo %s <target_ip> [-p src_port]\n", prog_name);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "\t-p    custom source port (default: 5132)\n");
    fprintf(stderr, "note: ip addr in common format (e.g 192.0.0.0)\n");
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        fprintf(stderr, "error: this program requires sudo!\n");
        return EXIT_FAILURE;
    }
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    char *target_ip = argv[1];
    int sport = SRC_PORT; int opt;
    optind = 2; 

    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                sport = atoi(optarg);
                if (sport <= 0 || sport > 65535) {
                    fprintf(stderr, "invalid source port\n");
                    return EXIT_FAILURE;
                }
                break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    uint32_t raw_daddr = ipchar2raw(target_ip);
    if (raw_daddr == 0) {
        fprintf(stderr, "invalid target ip\n");
        return EXIT_FAILURE;
    }

    scan(raw_daddr, target_ip);

    return EXIT_SUCCESS;
}