/*
 * sol_keygen.c - Solana keypair generation and management tool
 *
 * Usage:
 *   sol-keygen new [-o OUTFILE]           Generate new keypair
 *   sol-keygen pubkey KEYFILE             Show pubkey from keypair file
 *   sol-keygen verify KEYFILE             Verify keypair file is valid
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>

#include "util/sol_types.h"
#include "util/sol_err.h"
#include "crypto/sol_ed25519.h"
#include "txn/sol_pubkey.h"

#define VERSION "0.1.0"

/*
 * Print usage
 */
static void
print_usage(const char* progname) {
    fprintf(stderr,
        "sol-keygen %s - Solana keypair generation tool\n"
        "\n"
        "Usage:\n"
        "  %s new [-o OUTFILE] [--force]   Generate new keypair\n"
        "  %s pubkey KEYFILE               Show public key from keypair\n"
        "  %s verify KEYFILE               Verify keypair file\n"
        "  %s --help                       Show this help\n"
        "  %s --version                    Show version\n"
        "\n"
        "Options:\n"
        "  -o, --outfile PATH    Output keypair file (default: stdout for pubkey)\n"
        "  -f, --force           Overwrite existing file\n"
        "  -s, --silent          Don't print success messages\n"
        "\n"
        "Examples:\n"
        "  %s new -o ~/.config/solana/id.json\n"
        "  %s pubkey ~/.config/solana/id.json\n"
        "\n",
        VERSION, progname, progname, progname, progname, progname,
        progname, progname
    );
}

/*
 * Check if file exists
 */
static int
file_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/*
 * Generate new keypair
 */
static int
cmd_new(const char* outfile, int force, int silent) {
    /* Check if file exists */
    if (outfile && file_exists(outfile) && !force) {
        fprintf(stderr, "Error: File already exists: %s\n", outfile);
        fprintf(stderr, "Use --force to overwrite\n");
        return 1;
    }

    /* Generate keypair */
    sol_keypair_t keypair;
    sol_err_t err = sol_ed25519_keypair_generate(&keypair);
    if (err != SOL_OK) {
        fprintf(stderr, "Error: Failed to generate keypair: %s\n", sol_err_str(err));
        return 1;
    }

    /* Get pubkey */
    sol_pubkey_t pubkey;
    sol_ed25519_pubkey_from_keypair(&keypair, &pubkey);

    char pubkey_str[SOL_PUBKEY_BASE58_LEN];
    sol_pubkey_to_base58(&pubkey, pubkey_str, sizeof(pubkey_str));

    /* Save to file or print */
    if (outfile) {
        err = sol_ed25519_keypair_save(outfile, &keypair);
        if (err != SOL_OK) {
            fprintf(stderr, "Error: Failed to save keypair: %s\n", sol_err_str(err));
            return 1;
        }

        if (!silent) {
            printf("Wrote new keypair to %s\n", outfile);
            printf("pubkey: %s\n", pubkey_str);
        } else {
            printf("%s\n", pubkey_str);
        }
    } else {
        /* Just print the pubkey to stdout */
        printf("%s\n", pubkey_str);

        /* Also print JSON to stderr so it can be captured */
        fprintf(stderr, "[");
        for (int i = 0; i < 64; i++) {
            fprintf(stderr, "%u%s", keypair.bytes[i], i < 63 ? "," : "");
        }
        fprintf(stderr, "]\n");
    }

    /* Clear keypair from memory */
    memset(&keypair, 0, sizeof(keypair));

    return 0;
}

/*
 * Show pubkey from keypair file
 */
static int
cmd_pubkey(const char* keyfile) {
    if (!keyfile) {
        fprintf(stderr, "Error: No keypair file specified\n");
        return 1;
    }

    /* Load keypair */
    sol_keypair_t keypair;
    sol_err_t err = sol_ed25519_keypair_load(keyfile, &keypair);
    if (err != SOL_OK) {
        fprintf(stderr, "Error: Failed to load keypair: %s\n", sol_err_str(err));
        return 1;
    }

    /* Get pubkey */
    sol_pubkey_t pubkey;
    sol_ed25519_pubkey_from_keypair(&keypair, &pubkey);

    char pubkey_str[SOL_PUBKEY_BASE58_LEN];
    sol_pubkey_to_base58(&pubkey, pubkey_str, sizeof(pubkey_str));

    printf("%s\n", pubkey_str);

    /* Clear keypair from memory */
    memset(&keypair, 0, sizeof(keypair));

    return 0;
}

/*
 * Verify keypair file
 */
static int
cmd_verify(const char* keyfile) {
    if (!keyfile) {
        fprintf(stderr, "Error: No keypair file specified\n");
        return 1;
    }

    /* Load keypair */
    sol_keypair_t keypair;
    sol_err_t err = sol_ed25519_keypair_load(keyfile, &keypair);
    if (err != SOL_OK) {
        fprintf(stderr, "Error: Failed to load keypair: %s\n", sol_err_str(err));
        return 1;
    }

    /* Verify by signing and verifying a test message */
    const char* test_msg = "keypair verification test";
    sol_signature_t sig;
    sol_ed25519_sign(&keypair, (const uint8_t*)test_msg, strlen(test_msg), &sig);

    sol_pubkey_t pubkey;
    sol_ed25519_pubkey_from_keypair(&keypair, &pubkey);

    bool valid = sol_ed25519_verify(&pubkey, (const uint8_t*)test_msg, strlen(test_msg), &sig);

    /* Clear keypair from memory */
    memset(&keypair, 0, sizeof(keypair));

    if (valid) {
        char pubkey_str[SOL_PUBKEY_BASE58_LEN];
        sol_pubkey_to_base58(&pubkey, pubkey_str, sizeof(pubkey_str));
        printf("Keypair verified: %s\n", pubkey_str);
        return 0;
    } else {
        fprintf(stderr, "Error: Keypair verification failed\n");
        return 1;
    }
}

int
main(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"outfile", required_argument, 0, 'o'},
        {"force",   no_argument,       0, 'f'},
        {"silent",  no_argument,       0, 's'},
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    const char* outfile = NULL;
    int force = 0;
    int silent = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "o:fshV", long_options, NULL)) != -1) {
        switch (opt) {
        case 'o':
            outfile = optarg;
            break;
        case 'f':
            force = 1;
            break;
        case 's':
            silent = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'V':
            printf("sol-keygen %s\n", VERSION);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Get subcommand */
    if (optind >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    const char* cmd = argv[optind];
    const char* arg = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    if (strcmp(cmd, "new") == 0) {
        return cmd_new(outfile, force, silent);
    } else if (strcmp(cmd, "pubkey") == 0) {
        return cmd_pubkey(arg);
    } else if (strcmp(cmd, "verify") == 0) {
        return cmd_verify(arg);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
