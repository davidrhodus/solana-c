/*
 * sol_vote_tool.c - Vote account management tool
 *
 * Usage:
 *   sol-vote create --identity ID --vote-keypair VOTE
 *   sol-vote show VOTE_PUBKEY
 *   sol-vote update-commission --vote-keypair VOTE --commission PCT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "util/sol_types.h"
#include "util/sol_err.h"
#include "crypto/sol_ed25519.h"
#include "txn/sol_pubkey.h"
#include "programs/sol_vote_program.h"

#define VERSION "0.1.0"

/*
 * Print usage
 */
static void
print_usage(const char* progname) {
    fprintf(stderr,
        "sol-vote %s - Vote account management tool\n"
        "\n"
        "Usage:\n"
        "  %s create-keypair -o OUTFILE      Generate vote account keypair\n"
        "  %s init --keypair VOTE --identity ID [--commission PCT]\n"
        "                                     Initialize vote account (prints tx)\n"
        "  %s show VOTE_PUBKEY               Show vote account info\n"
        "  %s pubkey VOTE_KEYPAIR            Show vote account pubkey\n"
        "  %s --help                         Show this help\n"
        "  %s --version                      Show version\n"
        "\n"
        "Options:\n"
        "  -k, --keypair PATH    Vote account keypair file\n"
        "  -i, --identity PATH   Validator identity keypair file\n"
        "  -o, --outfile PATH    Output file for create-keypair\n"
        "  -c, --commission PCT  Commission percentage (0-100, default: 10)\n"
        "  -f, --force           Overwrite existing files\n"
        "\n"
        "Examples:\n"
        "  # Generate vote account keypair\n"
        "  %s create-keypair -o vote.json\n"
        "\n"
        "  # Show pubkey from vote keypair\n"
        "  %s pubkey vote.json\n"
        "\n"
        "  # Initialize vote account (outputs transaction hex)\n"
        "  %s init --keypair vote.json --identity id.json\n"
        "\n",
        VERSION, progname, progname, progname, progname, progname, progname,
        progname, progname, progname
    );
}

/*
 * Generate vote account keypair (same as keygen but specific to vote)
 */
static int
cmd_create_keypair(const char* outfile, int force) {
    if (!outfile) {
        fprintf(stderr, "Error: Output file required (-o OUTFILE)\n");
        return 1;
    }

    /* Check if file exists */
    FILE* f = fopen(outfile, "r");
    if (f && !force) {
        fclose(f);
        fprintf(stderr, "Error: File already exists: %s\n", outfile);
        fprintf(stderr, "Use --force to overwrite\n");
        return 1;
    }
    if (f) fclose(f);

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

    /* Save to file */
    err = sol_ed25519_keypair_save(outfile, &keypair);
    if (err != SOL_OK) {
        fprintf(stderr, "Error: Failed to save keypair: %s\n", sol_err_str(err));
        memset(&keypair, 0, sizeof(keypair));
        return 1;
    }

    printf("Vote keypair saved to: %s\n", outfile);
    printf("Vote account: %s\n", pubkey_str);

    /* Clear keypair from memory */
    memset(&keypair, 0, sizeof(keypair));

    return 0;
}

/*
 * Show pubkey from vote keypair file
 */
static int
cmd_pubkey(const char* keyfile) {
    if (!keyfile) {
        fprintf(stderr, "Error: Vote keypair file required\n");
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
 * Show vote account info (placeholder - requires RPC)
 */
static int
cmd_show(const char* vote_pubkey_str) {
    if (!vote_pubkey_str) {
        fprintf(stderr, "Error: Vote account pubkey required\n");
        return 1;
    }

    sol_pubkey_t pubkey;
    sol_err_t err = sol_pubkey_from_base58(vote_pubkey_str, &pubkey);
    if (err != SOL_OK) {
        fprintf(stderr, "Error: Invalid pubkey: %s\n", vote_pubkey_str);
        return 1;
    }

    printf("Vote Account: %s\n", vote_pubkey_str);
    printf("\nNote: Full account info requires RPC connection.\n");
    printf("Use: curl -X POST -H \"Content-Type: application/json\" \\\n");
    printf("     -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"%s\"]}' \\\n", vote_pubkey_str);
    printf("     http://localhost:8899\n");

    return 0;
}

/*
 * Initialize vote account (outputs transaction data)
 */
static int
cmd_init(const char* vote_keypair_path, const char* identity_path, uint8_t commission) {
    if (!vote_keypair_path) {
        fprintf(stderr, "Error: Vote keypair required (--keypair)\n");
        return 1;
    }
    if (!identity_path) {
        fprintf(stderr, "Error: Identity keypair required (--identity)\n");
        return 1;
    }

    /* Load vote keypair */
    sol_keypair_t vote_keypair;
    sol_err_t err = sol_ed25519_keypair_load(vote_keypair_path, &vote_keypair);
    if (err != SOL_OK) {
        fprintf(stderr, "Error: Failed to load vote keypair: %s\n", sol_err_str(err));
        return 1;
    }

    /* Load identity keypair */
    sol_keypair_t identity_keypair;
    err = sol_ed25519_keypair_load(identity_path, &identity_keypair);
    if (err != SOL_OK) {
        fprintf(stderr, "Error: Failed to load identity keypair: %s\n", sol_err_str(err));
        memset(&vote_keypair, 0, sizeof(vote_keypair));
        return 1;
    }

    /* Get pubkeys */
    sol_pubkey_t vote_pubkey, identity_pubkey;
    sol_ed25519_pubkey_from_keypair(&vote_keypair, &vote_pubkey);
    sol_ed25519_pubkey_from_keypair(&identity_keypair, &identity_pubkey);

    char vote_str[SOL_PUBKEY_BASE58_LEN];
    char identity_str[SOL_PUBKEY_BASE58_LEN];
    sol_pubkey_to_base58(&vote_pubkey, vote_str, sizeof(vote_str));
    sol_pubkey_to_base58(&identity_pubkey, identity_str, sizeof(identity_str));

    printf("Vote Account:    %s\n", vote_str);
    printf("Node Identity:   %s\n", identity_str);
    printf("Commission:      %u%%\n", commission);
    printf("\n");
    printf("To initialize this vote account, use the Solana CLI:\n");
    printf("\n");
    printf("  solana create-vote-account \\\n");
    printf("    --keypair %s \\\n", identity_path);
    printf("    %s \\\n", vote_keypair_path);
    printf("    %s \\\n", identity_str);
    printf("    %s \\\n", identity_str);  /* authorized_withdrawer = identity for simplicity */
    printf("    --commission %u\n", commission);
    printf("\n");
    printf("Or with sol-cli (if available):\n");
    printf("\n");
    printf("  sol-cli vote create \\\n");
    printf("    --vote-keypair %s \\\n", vote_keypair_path);
    printf("    --identity %s \\\n", identity_path);
    printf("    --commission %u\n", commission);

    /* Clear keypairs from memory */
    memset(&vote_keypair, 0, sizeof(vote_keypair));
    memset(&identity_keypair, 0, sizeof(identity_keypair));

    return 0;
}

int
main(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"keypair",    required_argument, 0, 'k'},
        {"identity",   required_argument, 0, 'i'},
        {"outfile",    required_argument, 0, 'o'},
        {"commission", required_argument, 0, 'c'},
        {"force",      no_argument,       0, 'f'},
        {"help",       no_argument,       0, 'h'},
        {"version",    no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    const char* keypair_path = NULL;
    const char* identity_path = NULL;
    const char* outfile = NULL;
    uint8_t commission = 10;  /* Default 10% */
    int force = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "k:i:o:c:fhV", long_options, NULL)) != -1) {
        switch (opt) {
        case 'k':
            keypair_path = optarg;
            break;
        case 'i':
            identity_path = optarg;
            break;
        case 'o':
            outfile = optarg;
            break;
        case 'c':
            commission = (uint8_t)atoi(optarg);
            if (commission > 100) {
                fprintf(stderr, "Error: Commission must be 0-100\n");
                return 1;
            }
            break;
        case 'f':
            force = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'V':
            printf("sol-vote %s\n", VERSION);
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

    if (strcmp(cmd, "create-keypair") == 0) {
        return cmd_create_keypair(outfile, force);
    } else if (strcmp(cmd, "pubkey") == 0) {
        return cmd_pubkey(arg);
    } else if (strcmp(cmd, "show") == 0) {
        return cmd_show(arg);
    } else if (strcmp(cmd, "init") == 0) {
        return cmd_init(keypair_path, identity_path, commission);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
