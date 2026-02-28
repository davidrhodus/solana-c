# Solana Mainnet Validator Implementation in Pure C

## Project Overview

A complete implementation of a Solana mainnet validator written in pure C (C17 standard). This implementation aims to be fully compatible with the existing Solana network, capable of participating in consensus, processing transactions, and serving RPC requests.

---

## Table of Contents

1. [Goals and Non-Goals](#goals-and-non-goals)
2. [Architecture Overview](#architecture-overview)
3. [Core Components](#core-components)
4. [Data Structures](#data-structures)
5. [Networking Layer](#networking-layer)
6. [Consensus Implementation](#consensus-implementation)
7. [Transaction Processing](#transaction-processing)
8. [Account Storage](#account-storage)
9. [Runtime and BPF VM](#runtime-and-bpf-vm)
10. [RPC Interface](#rpc-interface)
11. [Cryptographic Primitives](#cryptographic-primitives)
12. [Dependencies](#dependencies)
13. [Build System](#build-system)
14. [Testing Strategy](#testing-strategy)
15. [Performance Targets](#performance-targets)

---

## Goals and Non-Goals

### Goals

- Full mainnet compatibility with Solana protocol v1.18+
- Pure C implementation (C17 standard, no C++ code)
- Production-ready validator capable of:
  - Participating in Tower BFT consensus
  - Processing and validating transactions
  - Maintaining account state (AccountsDB)
  - Serving JSON-RPC requests
  - Gossip protocol participation
  - Block production (when elected leader)
  - Snapshot generation and loading
- Performance parity with reference Rust implementation
- Memory-efficient design suitable for commodity hardware
- Clean, auditable codebase

### Non-Goals

- GUI or graphical tools (CLI only)
- Wallet functionality (separate project)
- Custom modifications to Solana protocol
- Support for deprecated/legacy features

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Validator Node                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   RPC API   │  │   Gossip    │  │      TPU / TVU          │  │
│  │  (JSON-RPC) │  │  Protocol   │  │  (Transaction Units)    │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘  │
│         │                │                     │                │
│  ┌──────┴────────────────┴─────────────────────┴──────────────┐ │
│  │                    Core Runtime                             │ │
│  ├─────────────────────────────────────────────────────────────┤ │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌──────────┐ │ │
│  │  │  Tower    │  │   Bank    │  │  Replay   │  │  Leader  │ │ │
│  │  │   BFT     │  │  Runtime  │  │   Stage   │  │ Schedule │ │ │
│  │  └───────────┘  └───────────┘  └───────────┘  └──────────┘ │ │
│  └─────────────────────────────────────────────────────────────┘ │
│         │                │                     │                │
│  ┌──────┴────────────────┴─────────────────────┴──────────────┐ │
│  │                   Storage Layer                             │ │
│  ├─────────────────────────────────────────────────────────────┤ │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌──────────┐ │ │
│  │  │ Accounts  │  │  Blockstore│ │  Snapshots│  │   WAL    │ │ │
│  │  │    DB     │  │           │  │           │  │          │ │ │
│  │  └───────────┘  └───────────┘  └───────────┘  └──────────┘ │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Module Organization

```
solana-c/
├── src/
│   ├── core/               # Core types and utilities
│   │   ├── types.h         # Fundamental types (Pubkey, Hash, Signature)
│   │   ├── error.h         # Error handling
│   │   ├── memory.h        # Memory management
│   │   └── log.h           # Logging infrastructure
│   │
│   ├── crypto/             # Cryptographic operations
│   │   ├── ed25519.h       # Ed25519 signatures
│   │   ├── sha256.h        # SHA-256 hashing
│   │   ├── keccak.h        # Keccak/SHA-3
│   │   ├── secp256k1.h     # secp256k1 recovery
│   │   └── aes.h           # AES-GCM for shred encryption
│   │
│   ├── net/                # Networking
│   │   ├── gossip.h        # Gossip protocol
│   │   ├── tpu.h           # Transaction Processing Unit
│   │   ├── tvu.h           # Transaction Validation Unit
│   │   ├── repair.h        # Block repair protocol
│   │   ├── quic.h          # QUIC transport
│   │   └── udp.h           # UDP transport
│   │
│   ├── consensus/          # Consensus mechanisms
│   │   ├── tower.h         # Tower BFT
│   │   ├── vote.h          # Vote processing
│   │   ├── stakes.h        # Stake tracking
│   │   └── leader_schedule.h
│   │
│   ├── runtime/            # Transaction runtime
│   │   ├── bank.h          # Bank (slot state)
│   │   ├── executor.h      # Transaction executor
│   │   ├── sysvar.h        # System variables
│   │   └── builtin/        # Native programs
│   │       ├── system.h
│   │       ├── stake.h
│   │       ├── vote.h
│   │       ├── bpf_loader.h
│   │       └── ...
│   │
│   ├── bpf/                # BPF Virtual Machine
│   │   ├── vm.h            # BPF interpreter/JIT
│   │   ├── syscalls.h      # Syscall implementations
│   │   ├── memory.h        # BPF memory model
│   │   └── verifier.h      # Bytecode verification
│   │
│   ├── storage/            # Persistent storage
│   │   ├── accounts_db.h   # Account storage
│   │   ├── blockstore.h    # Block/shred storage
│   │   ├── snapshot.h      # Snapshot handling
│   │   └── wal.h           # Write-ahead log
│   │
│   ├── rpc/                # RPC interface
│   │   ├── server.h        # HTTP/WebSocket server
│   │   ├── handlers.h      # RPC method handlers
│   │   └── pubsub.h        # PubSub subscriptions
│   │
│   └── validator/          # Validator orchestration
│       ├── main.c          # Entry point
│       ├── config.h        # Configuration
│       ├── replay.h        # Replay stage
│       └── stages.h        # Pipeline stages
│
├── include/                # Public headers
├── lib/                    # Third-party libraries
├── tests/                  # Test suites
├── bench/                  # Benchmarks
└── tools/                  # CLI utilities
```

---

## Core Components

### 1. Types Module (`src/core/types.h`)

```c
#include <stdint.h>
#include <stdbool.h>

/* Fundamental sizes */
#define SOL_PUBKEY_SIZE      32
#define SOL_SIGNATURE_SIZE   64
#define SOL_HASH_SIZE        32
#define SOL_KEYPAIR_SIZE     64

/* Public key */
typedef struct {
    uint8_t bytes[SOL_PUBKEY_SIZE];
} sol_pubkey_t;

/* Cryptographic hash */
typedef struct {
    uint8_t bytes[SOL_HASH_SIZE];
} sol_hash_t;

/* Ed25519 signature */
typedef struct {
    uint8_t bytes[SOL_SIGNATURE_SIZE];
} sol_signature_t;

/* Keypair */
typedef struct {
    uint8_t bytes[SOL_KEYPAIR_SIZE];
} sol_keypair_t;

/* Slot number */
typedef uint64_t sol_slot_t;

/* Epoch number */
typedef uint64_t sol_epoch_t;

/* Lamports (native token unit) */
typedef uint64_t sol_lamports_t;

/* Unix timestamp */
typedef int64_t sol_unix_timestamp_t;

/* Account metadata */
typedef struct {
    sol_lamports_t  lamports;
    uint64_t        data_len;
    sol_pubkey_t    owner;
    bool            executable;
    sol_epoch_t     rent_epoch;
} sol_account_meta_t;

/* Account with data */
typedef struct {
    sol_account_meta_t meta;
    uint8_t*           data;
} sol_account_t;

/* Transaction instruction */
typedef struct {
    uint8_t   program_id_index;
    uint8_t*  account_indices;
    uint8_t   account_indices_len;
    uint8_t*  data;
    uint32_t  data_len;
} sol_instruction_t;

/* Compiled transaction message */
typedef struct {
    uint8_t            header_num_required_signatures;
    uint8_t            header_num_readonly_signed;
    uint8_t            header_num_readonly_unsigned;
    sol_pubkey_t*      account_keys;
    uint8_t            account_keys_len;
    sol_hash_t         recent_blockhash;
    sol_instruction_t* instructions;
    uint8_t            instructions_len;
} sol_message_t;

/* Versioned transaction */
typedef struct {
    uint8_t          version;  /* 0 = legacy, 1+ = versioned */
    sol_message_t    message;
    sol_signature_t* signatures;
    uint8_t          signatures_len;
} sol_transaction_t;
```

### 2. Error Handling (`src/core/error.h`)

```c
typedef enum {
    SOL_OK = 0,

    /* General errors */
    SOL_ERR_NOMEM,
    SOL_ERR_INVALID_PARAM,
    SOL_ERR_IO,
    SOL_ERR_TIMEOUT,

    /* Crypto errors */
    SOL_ERR_INVALID_SIGNATURE,
    SOL_ERR_INVALID_PUBKEY,

    /* Transaction errors */
    SOL_ERR_TX_MALFORMED,
    SOL_ERR_TX_SIGNATURE_FAILURE,
    SOL_ERR_TX_BLOCKHASH_NOT_FOUND,
    SOL_ERR_TX_INSUFFICIENT_FUNDS,
    SOL_ERR_TX_DUPLICATE,
    SOL_ERR_TX_ACCOUNT_NOT_FOUND,
    SOL_ERR_TX_PROGRAM_FAILED,

    /* Consensus errors */
    SOL_ERR_SLOT_SKIPPED,
    SOL_ERR_FORK_DETECTED,
    SOL_ERR_VOTE_INVALID,

    /* Storage errors */
    SOL_ERR_BLOCKSTORE_FULL,
    SOL_ERR_SNAPSHOT_CORRUPT,

    /* Network errors */
    SOL_ERR_PEER_UNAVAILABLE,
    SOL_ERR_GOSSIP_INVALID,

    SOL_ERR_MAX
} sol_error_t;

/* Error context for detailed reporting */
typedef struct {
    sol_error_t  code;
    const char*  message;
    const char*  file;
    int          line;
} sol_error_ctx_t;

#define SOL_TRY(expr) do { \
    sol_error_t _err = (expr); \
    if (_err != SOL_OK) return _err; \
} while(0)
```

---

## Data Structures

### Core Data Structures Required

| Structure | Description | Header |
|-----------|-------------|--------|
| `sol_hashmap_t` | High-performance hash map | `core/hashmap.h` |
| `sol_vec_t` | Dynamic array | `core/vec.h` |
| `sol_arena_t` | Arena allocator | `core/arena.h` |
| `sol_queue_t` | Lock-free queue | `core/queue.h` |
| `sol_bloom_t` | Bloom filter | `core/bloom.h` |
| `sol_btree_t` | B-tree for ordered data | `core/btree.h` |
| `sol_lru_t` | LRU cache | `core/lru.h` |
| `sol_bitset_t` | Bit set | `core/bitset.h` |

### Hash Map Implementation Requirements

- Open addressing with Robin Hood hashing
- SIMD-accelerated probe sequences (SSE4.2/AVX2)
- Power-of-two sizing for fast modulo
- Tombstone-free deletion using backward shift
- Configurable load factor (default 0.875)
- Support for custom hash functions

---

## Networking Layer

### Gossip Protocol (`src/net/gossip.h`)

The gossip protocol maintains cluster state through epidemic communication.

```c
/* Gossip message types */
typedef enum {
    SOL_GOSSIP_PULL_REQUEST,
    SOL_GOSSIP_PULL_RESPONSE,
    SOL_GOSSIP_PUSH,
    SOL_GOSSIP_PRUNE,
    SOL_GOSSIP_PING,
    SOL_GOSSIP_PONG,
} sol_gossip_msg_type_t;

/* Cluster info data types */
typedef enum {
    SOL_CRDS_CONTACT_INFO,
    SOL_CRDS_VOTE,
    SOL_CRDS_LOWEST_SLOT,
    SOL_CRDS_SNAPSHOT_HASHES,
    SOL_CRDS_EPOCH_SLOTS,
    SOL_CRDS_LEGACY_VERSION,
    SOL_CRDS_VERSION,
    SOL_CRDS_NODE_INSTANCE,
    SOL_CRDS_DUPLICATE_SHRED,
    SOL_CRDS_INCREMENTAL_SNAPSHOT_HASHES,
} sol_crds_data_type_t;

/* Contact info structure */
typedef struct {
    sol_pubkey_t     pubkey;
    uint64_t         wallclock;
    uint16_t         shred_version;

    /* Network endpoints */
    struct sockaddr_in6 gossip;
    struct sockaddr_in6 tvu;
    struct sockaddr_in6 tvu_forwards;
    struct sockaddr_in6 repair;
    struct sockaddr_in6 tpu;
    struct sockaddr_in6 tpu_forwards;
    struct sockaddr_in6 tpu_vote;
    struct sockaddr_in6 rpc;
    struct sockaddr_in6 rpc_pubsub;
    struct sockaddr_in6 serve_repair;
} sol_contact_info_t;

/* Gossip service interface */
typedef struct sol_gossip sol_gossip_t;

sol_gossip_t* sol_gossip_create(const sol_gossip_config_t* config);
void          sol_gossip_destroy(sol_gossip_t* gossip);
sol_error_t   sol_gossip_start(sol_gossip_t* gossip);
sol_error_t   sol_gossip_stop(sol_gossip_t* gossip);
sol_error_t   sol_gossip_push(sol_gossip_t* gossip, const sol_crds_value_t* value);
```

### Transport Protocols

#### QUIC Transport (`src/net/quic.h`)

QUIC is the primary transport for TPU (transaction ingestion).

```c
typedef struct sol_quic_endpoint sol_quic_endpoint_t;
typedef struct sol_quic_connection sol_quic_connection_t;
typedef struct sol_quic_stream sol_quic_stream_t;

/* QUIC endpoint configuration */
typedef struct {
    struct sockaddr_in6  bind_addr;
    sol_keypair_t*       identity;          /* For TLS */
    uint32_t             max_connections;
    uint32_t             max_streams_per_conn;
    uint32_t             idle_timeout_ms;
} sol_quic_config_t;

sol_quic_endpoint_t* sol_quic_endpoint_create(const sol_quic_config_t* config);
```

#### UDP Transport (`src/net/udp.h`)

UDP used for gossip, TVU (shred receiving), and repair.

```c
typedef struct sol_udp_socket sol_udp_socket_t;

sol_udp_socket_t* sol_udp_create(const struct sockaddr_in6* bind_addr);
sol_error_t       sol_udp_send(sol_udp_socket_t* sock,
                               const void* data, size_t len,
                               const struct sockaddr_in6* dest);
sol_error_t       sol_udp_recv(sol_udp_socket_t* sock,
                               void* buf, size_t buf_len, size_t* recv_len,
                               struct sockaddr_in6* src);
```

### Shred Protocol

Shreds are the fundamental unit of block data transmission.

```c
#define SOL_SHRED_DATA_CAPACITY   1051
#define SOL_SHRED_CODE_CAPACITY   1228
#define SOL_SHRED_HEADER_SIZE     88

typedef enum {
    SOL_SHRED_TYPE_DATA = 0b10100101,
    SOL_SHRED_TYPE_CODE = 0b01011010,
} sol_shred_type_t;

typedef struct {
    sol_signature_t signature;
    uint8_t         variant;
    sol_slot_t      slot;
    uint32_t        index;
    uint16_t        version;
    uint32_t        fec_set_index;
    /* ... additional fields based on variant */
} sol_shred_header_t;

typedef struct {
    sol_shred_header_t header;
    uint8_t            payload[SOL_SHRED_DATA_CAPACITY];
    uint16_t           payload_len;
} sol_shred_t;

/* Reed-Solomon erasure coding */
sol_error_t sol_shred_recover(sol_shred_t** shreds, size_t count,
                               sol_shred_t** recovered, size_t* recovered_count);
```

---

## Consensus Implementation

### Tower BFT (`src/consensus/tower.h`)

Tower BFT is Solana's proof-of-stake consensus mechanism.

```c
/* Vote state for a validator */
typedef struct {
    sol_pubkey_t    node_pubkey;
    sol_pubkey_t    authorized_voter;
    sol_pubkey_t    authorized_withdrawer;
    uint8_t         commission;

    /* Vote lockout tower */
    struct {
        sol_slot_t  slot;
        uint32_t    confirmation_count;
    } votes[32];  /* MAX_LOCKOUT_HISTORY */
    uint8_t         votes_len;

    sol_slot_t      root_slot;
    sol_hash_t      root_hash;

    /* Epoch credits */
    struct {
        sol_epoch_t epoch;
        uint64_t    credits;
        uint64_t    prev_credits;
    } epoch_credits[64];
    uint8_t         epoch_credits_len;

    sol_lamports_t  last_timestamp_slot;
    sol_unix_timestamp_t last_timestamp;
} sol_vote_state_t;

/* Tower state for local validator */
typedef struct {
    sol_vote_state_t  vote_state;
    sol_slot_t        last_voted_slot;
    sol_hash_t        last_voted_hash;
    sol_slot_t        stray_restored_slot;
    sol_hash_t        last_vote_tx_blockhash;
} sol_tower_t;

/* Fork choice */
typedef struct sol_fork_choice sol_fork_choice_t;

sol_fork_choice_t* sol_fork_choice_create(void);
sol_slot_t         sol_fork_choice_best_slot(sol_fork_choice_t* fc);
sol_error_t        sol_fork_choice_add_vote(sol_fork_choice_t* fc,
                                             sol_slot_t slot,
                                             sol_lamports_t stake);
```

### Leader Schedule (`src/consensus/leader_schedule.h`)

```c
typedef struct {
    sol_epoch_t     epoch;
    sol_slot_t      first_slot;
    sol_slot_t      last_slot;
    sol_pubkey_t*   leaders;      /* One per slot in epoch */
    size_t          slot_count;
} sol_leader_schedule_t;

/* Generate leader schedule for epoch */
sol_error_t sol_leader_schedule_generate(
    sol_epoch_t epoch,
    const sol_stakes_t* stakes,
    sol_leader_schedule_t* out
);

/* Get leader for specific slot */
const sol_pubkey_t* sol_leader_schedule_get(
    const sol_leader_schedule_t* schedule,
    sol_slot_t slot
);
```

---

## Transaction Processing

### Bank (`src/runtime/bank.h`)

The Bank represents the state of the ledger at a specific slot.

```c
typedef struct sol_bank sol_bank_t;

/* Bank configuration */
typedef struct {
    sol_slot_t              slot;
    sol_hash_t              blockhash;
    sol_hash_t              parent_hash;
    sol_epoch_t             epoch;
    uint64_t                block_height;
    sol_unix_timestamp_t    unix_timestamp;
    sol_lamports_t          capitalization;
    sol_lamports_t          max_tick_height;
    uint64_t                ticks_per_slot;
    uint64_t                ns_per_slot;
    uint64_t                slots_per_epoch;
} sol_bank_config_t;

/* Create bank from parent */
sol_bank_t* sol_bank_new_from_parent(
    sol_bank_t* parent,
    sol_slot_t slot,
    const sol_pubkey_t* collector_id
);

/* Freeze bank after all transactions processed */
sol_error_t sol_bank_freeze(sol_bank_t* bank);

/* Get bank hash */
sol_hash_t sol_bank_hash(const sol_bank_t* bank);

/* Account access */
sol_account_t* sol_bank_get_account(sol_bank_t* bank, const sol_pubkey_t* pubkey);
sol_error_t    sol_bank_store_account(sol_bank_t* bank,
                                       const sol_pubkey_t* pubkey,
                                       const sol_account_t* account);
```

### Transaction Executor (`src/runtime/executor.h`)

```c
/* Transaction execution result */
typedef struct {
    sol_error_t     status;
    uint64_t        compute_units_consumed;
    uint64_t        fee;

    /* Return data from programs */
    sol_pubkey_t    return_data_program_id;
    uint8_t*        return_data;
    size_t          return_data_len;

    /* Log messages */
    char**          logs;
    size_t          logs_len;

    /* Inner instructions (CPI) */
    /* ... */
} sol_tx_result_t;

/* Execute a batch of transactions */
sol_error_t sol_execute_batch(
    sol_bank_t* bank,
    const sol_transaction_t* transactions,
    size_t transaction_count,
    sol_tx_result_t* results
);

/* Verify transaction signatures */
sol_error_t sol_verify_signatures(
    const sol_transaction_t* tx,
    bool* valid
);

/* Check transaction sanity */
sol_error_t sol_sanitize_transaction(
    const sol_transaction_t* tx
);
```

### Native Programs (`src/runtime/builtin/`)

Built-in programs that must be implemented:

| Program | Address | Description |
|---------|---------|-------------|
| System | `11111111111111111111111111111111` | Account creation, SOL transfers |
| Stake | `Stake11111111111111111111111111111111111111` | Stake delegation |
| Vote | `Vote111111111111111111111111111111111111111` | Voting/consensus |
| BPF Loader | `BPFLoader2111111111111111111111111111111111` | Deploy/execute BPF programs |
| Config | `Config1111111111111111111111111111111111111` | On-chain configuration |
| Compute Budget | `ComputeBudget111111111111111111111111111111` | Compute limits |
| Address Lookup Table | `AddressLookupTab1e1111111111111111111111111` | ALT for versioned tx |
| Ed25519 | `Ed25519SigVerify111111111111111111111111111` | Signature verification precompile |
| Secp256k1 | `KeccakSecp256k11111111111111111111111111111` | Ethereum signature recovery |

---

## Account Storage

### AccountsDB (`src/storage/accounts_db.h`)

High-performance account storage with append-only semantics.

```c
typedef struct sol_accounts_db sol_accounts_db_t;

/* Storage configuration */
typedef struct {
    const char*     path;
    size_t          cache_size_bytes;
    uint32_t        num_shards;          /* For parallel access */
    bool            enable_compression;
    uint32_t        accounts_per_file;   /* Append vec sizing */
} sol_accounts_db_config_t;

sol_accounts_db_t* sol_accounts_db_open(const sol_accounts_db_config_t* config);
void               sol_accounts_db_close(sol_accounts_db_t* db);

/* Account operations */
sol_error_t sol_accounts_db_load(
    sol_accounts_db_t* db,
    const sol_pubkey_t* pubkey,
    sol_slot_t ancestor_slot,
    sol_account_t** account
);

sol_error_t sol_accounts_db_store(
    sol_accounts_db_t* db,
    sol_slot_t slot,
    const sol_pubkey_t* pubkey,
    const sol_account_t* account
);

/* Clean dead slots and reclaim space */
sol_error_t sol_accounts_db_clean(sol_accounts_db_t* db, sol_slot_t max_clean_root);

/* Account indexing */
typedef struct {
    sol_slot_t  slot;
    uint64_t    offset;
    uint32_t    file_id;
} sol_account_index_entry_t;
```

### Blockstore (`src/storage/blockstore.h`)

Stores shreds and assembled blocks.

```c
typedef struct sol_blockstore sol_blockstore_t;

/* Blockstore backed by RocksDB-compatible storage */
sol_blockstore_t* sol_blockstore_open(const char* path);
void              sol_blockstore_close(sol_blockstore_t* bs);

/* Shred operations */
sol_error_t sol_blockstore_insert_shreds(
    sol_blockstore_t* bs,
    const sol_shred_t* shreds,
    size_t count
);

sol_error_t sol_blockstore_get_data_shreds(
    sol_blockstore_t* bs,
    sol_slot_t slot,
    uint32_t start_index,
    uint32_t end_index,
    sol_shred_t** shreds,
    size_t* count
);

/* Slot metadata */
typedef struct {
    sol_slot_t      slot;
    sol_slot_t      parent_slot;
    sol_hash_t      blockhash;
    bool            is_full;
    bool            is_rooted;
    uint64_t        num_shreds;
    uint64_t        num_entries;
    uint64_t        num_transactions;
} sol_slot_meta_t;

sol_error_t sol_blockstore_get_slot_meta(
    sol_blockstore_t* bs,
    sol_slot_t slot,
    sol_slot_meta_t* meta
);
```

### Snapshots (`src/storage/snapshot.h`)

```c
typedef struct {
    sol_slot_t      slot;
    sol_hash_t      hash;
    sol_epoch_t     epoch;
    uint64_t        capitalization;

    /* Accounts data compressed with zstd */
    const char*     accounts_path;
    size_t          accounts_size;
} sol_snapshot_t;

/* Generate full snapshot */
sol_error_t sol_snapshot_create_full(
    const sol_bank_t* bank,
    const sol_accounts_db_t* accounts,
    const char* output_path
);

/* Generate incremental snapshot */
sol_error_t sol_snapshot_create_incremental(
    const sol_bank_t* bank,
    const sol_accounts_db_t* accounts,
    sol_slot_t base_slot,
    const char* output_path
);

/* Load snapshot */
sol_error_t sol_snapshot_load(
    const char* path,
    sol_bank_t** bank,
    sol_accounts_db_t** accounts
);
```

---

## Runtime and BPF VM

### BPF Virtual Machine (`src/bpf/vm.h`)

Execute eBPF programs (Solana BPF variant).

```c
typedef struct sol_bpf_vm sol_bpf_vm_t;

/* VM configuration */
typedef struct {
    uint64_t        compute_budget;
    uint64_t        heap_size;
    bool            enable_jit;          /* JIT compilation */
    bool            verify_mul64_imm;    /* SBPFv2 verification */
} sol_bpf_vm_config_t;

/* Executable program */
typedef struct {
    uint8_t*        bytecode;
    size_t          bytecode_len;
    uint64_t        entrypoint;
    /* JIT-compiled code cache */
    void*           jit_code;
    size_t          jit_size;
} sol_bpf_executable_t;

/* Verify and load program */
sol_error_t sol_bpf_verify(
    const uint8_t* bytecode,
    size_t len,
    sol_bpf_executable_t** exec
);

/* Execute program */
sol_error_t sol_bpf_execute(
    sol_bpf_vm_t* vm,
    const sol_bpf_executable_t* exec,
    sol_bpf_context_t* ctx,
    uint64_t* compute_consumed
);
```

### Syscalls (`src/bpf/syscalls.h`)

System calls available to BPF programs.

```c
/* Syscall numbers */
#define SOL_SYSCALL_ABORT                   0
#define SOL_SYSCALL_SOL_PANIC               1
#define SOL_SYSCALL_SOL_LOG                 2
#define SOL_SYSCALL_SOL_LOG_64              3
#define SOL_SYSCALL_SOL_LOG_PUBKEY          4
#define SOL_SYSCALL_SOL_LOG_COMPUTE_UNITS   5
#define SOL_SYSCALL_SOL_LOG_DATA            6
#define SOL_SYSCALL_SOL_CREATE_PROGRAM_ADDRESS    7
#define SOL_SYSCALL_SOL_TRY_FIND_PROGRAM_ADDRESS  8
#define SOL_SYSCALL_SOL_SHA256              9
#define SOL_SYSCALL_SOL_KECCAK256           10
#define SOL_SYSCALL_SOL_SECP256K1_RECOVER   11
#define SOL_SYSCALL_SOL_BLAKE3              12
#define SOL_SYSCALL_SOL_POSEIDON            13
#define SOL_SYSCALL_SOL_INVOKE_SIGNED       14
#define SOL_SYSCALL_SOL_ALLOC_FREE          15
#define SOL_SYSCALL_SOL_SET_RETURN_DATA     16
#define SOL_SYSCALL_SOL_GET_RETURN_DATA     17
#define SOL_SYSCALL_SOL_MEMCPY              18
#define SOL_SYSCALL_SOL_MEMCMP              19
#define SOL_SYSCALL_SOL_MEMSET              20
#define SOL_SYSCALL_SOL_GET_CLOCK_SYSVAR    21
#define SOL_SYSCALL_SOL_GET_EPOCH_SCHEDULE_SYSVAR 22
#define SOL_SYSCALL_SOL_GET_RENT_SYSVAR     23
/* ... additional syscalls */

/* Syscall handler type */
typedef uint64_t (*sol_syscall_handler_t)(
    sol_bpf_vm_t* vm,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
);

/* Register syscall handlers */
sol_error_t sol_bpf_register_syscalls(sol_bpf_vm_t* vm);
```

---

## RPC Interface

### JSON-RPC Server (`src/rpc/server.h`)

```c
typedef struct sol_rpc_server sol_rpc_server_t;

typedef struct {
    const char*     bind_address;
    uint16_t        port;
    uint32_t        max_connections;
    uint32_t        max_request_size;
    bool            enable_websocket;
    uint16_t        websocket_port;
} sol_rpc_config_t;

sol_rpc_server_t* sol_rpc_server_create(
    const sol_rpc_config_t* config,
    sol_bank_t* bank,
    sol_blockstore_t* blockstore
);

sol_error_t sol_rpc_server_start(sol_rpc_server_t* server);
sol_error_t sol_rpc_server_stop(sol_rpc_server_t* server);
```

### Required RPC Methods

**Account Methods:**
- `getAccountInfo`
- `getMultipleAccounts`
- `getProgramAccounts`
- `getBalance`
- `getTokenAccountBalance`
- `getTokenAccountsByOwner`

**Block Methods:**
- `getBlock`
- `getBlockHeight`
- `getBlockTime`
- `getBlocks`
- `getBlocksWithLimit`
- `getFirstAvailableBlock`

**Transaction Methods:**
- `getTransaction`
- `getSignaturesForAddress`
- `getSignatureStatuses`
- `sendTransaction`
- `simulateTransaction`

**Cluster Methods:**
- `getClusterNodes`
- `getEpochInfo`
- `getEpochSchedule`
- `getGenesisHash`
- `getHealth`
- `getIdentity`
- `getInflationGovernor`
- `getInflationRate`
- `getLeaderSchedule`
- `getRecentPerformanceSamples`
- `getSlot`
- `getSlotLeader`
- `getStakeActivation`
- `getSupply`
- `getVersion`
- `getVoteAccounts`

**Subscription Methods (WebSocket):**
- `accountSubscribe`
- `logsSubscribe`
- `programSubscribe`
- `signatureSubscribe`
- `slotSubscribe`
- `rootSubscribe`

---

## Cryptographic Primitives

### Required Implementations

| Algorithm | Usage | Library Recommendation |
|-----------|-------|----------------------|
| Ed25519 | Transaction signatures, validator identity | libsodium or custom |
| SHA-256 | Account hashing, blockhash | OpenSSL or custom |
| SHA-512 | Ed25519 internals | OpenSSL or custom |
| Keccak-256 | Ethereum compatibility | tiny_keccak port |
| Blake3 | Program derived addresses | BLAKE3 reference |
| Secp256k1 | Ethereum signature recovery | libsecp256k1 |
| AES-128-GCM | Shred encryption | OpenSSL or custom |
| ChaCha20-Poly1305 | QUIC encryption | OpenSSL or custom |
| Poseidon | ZK-proof compatibility | Custom implementation |

### Ed25519 Interface (`src/crypto/ed25519.h`)

```c
/* Generate keypair from seed */
sol_error_t sol_ed25519_keypair_from_seed(
    const uint8_t seed[32],
    sol_keypair_t* keypair
);

/* Sign message */
sol_error_t sol_ed25519_sign(
    const sol_keypair_t* keypair,
    const uint8_t* message,
    size_t message_len,
    sol_signature_t* signature
);

/* Verify signature */
sol_error_t sol_ed25519_verify(
    const sol_pubkey_t* pubkey,
    const uint8_t* message,
    size_t message_len,
    const sol_signature_t* signature,
    bool* valid
);

/* Batch verification (faster for multiple signatures) */
sol_error_t sol_ed25519_verify_batch(
    const sol_pubkey_t* pubkeys,
    const uint8_t** messages,
    const size_t* message_lens,
    const sol_signature_t* signatures,
    size_t count,
    bool* all_valid
);
```

---

## Dependencies

### Required External Libraries

| Library | Purpose | License |
|---------|---------|---------|
| libuv | Event loop / async I/O | MIT |
| OpenSSL/BoringSSL | TLS, crypto primitives | Apache 2.0 |
| zstd | Snapshot compression | BSD |
| lz4 | Fast compression | BSD |
| rocksdb | Blockstore backend (C API) | Apache 2.0 |
| libsodium | Ed25519, crypto | ISC |
| quiche | QUIC implementation | BSD |
| http-parser | HTTP parsing | MIT |
| cJSON | JSON parsing | MIT |

### Optional Libraries

| Library | Purpose | License |
|---------|---------|---------|
| jemalloc | Memory allocator | BSD |
| mimalloc | Memory allocator | MIT |
| liburing | Linux io_uring | LGPL/MIT |

---

## Build System

### Build Requirements

- CMake 3.20+
- C17 compliant compiler (GCC 11+, Clang 14+)
- POSIX-compliant OS (Linux primary, macOS secondary)

### CMake Structure

```cmake
cmake_minimum_required(VERSION 3.20)
project(solana-c VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -fno-omit-frame-pointer
    -march=native
)

# Build types
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -fsanitize=address,undefined")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -flto")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

# Library targets
add_library(solana_core STATIC
    src/core/types.c
    src/core/error.c
    # ...
)

add_library(solana_crypto STATIC
    src/crypto/ed25519.c
    src/crypto/sha256.c
    # ...
)

add_library(solana_net STATIC
    src/net/gossip.c
    src/net/tpu.c
    # ...
)

# Main validator executable
add_executable(solana-validator
    src/validator/main.c
)

target_link_libraries(solana-validator PRIVATE
    solana_core
    solana_crypto
    solana_net
    solana_consensus
    solana_runtime
    solana_storage
    solana_bpf
    solana_rpc
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)
```

---

## Testing Strategy

### Test Categories

1. **Unit Tests** - Individual function testing
2. **Integration Tests** - Component interaction
3. **Conformance Tests** - Protocol compatibility with reference implementation
4. **Fuzz Tests** - Input fuzzing for security
5. **Performance Tests** - Benchmarks and regression testing

### Test Framework

Use a lightweight C testing framework:

```c
/* tests/test_framework.h */
#define TEST(name) static void test_##name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)
```

### Conformance Testing

```c
/* Test against reference Solana implementation */
typedef struct {
    const char* name;
    const char* input_file;     /* Serialized transaction */
    const char* expected_file;  /* Expected execution result */
} sol_conformance_test_t;

/* Run conformance test suite */
sol_error_t sol_run_conformance_tests(const char* test_dir);
```

---

## Performance Targets

### Throughput Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Transaction verification | 100,000 TPS | Parallel signature verification |
| Transaction execution | 50,000 TPS | Native programs |
| BPF execution | 20,000 TPS | Simple programs |
| Shred processing | 10,000 shreds/sec | Including Reed-Solomon |
| Account reads | 500,000 ops/sec | Hot cache |
| Account writes | 100,000 ops/sec | Batched |

### Latency Targets

| Operation | Target (p99) |
|-----------|--------------|
| Signature verification | < 100 μs |
| Account lookup (cached) | < 10 μs |
| Account lookup (disk) | < 1 ms |
| Transaction execution | < 500 μs |
| Block processing | < 400 ms |

### Memory Targets

| Component | Target |
|-----------|--------|
| Base validator | < 16 GB |
| Account cache | Configurable (8-64 GB) |
| BPF VM heap | 32 KB per execution |
| Network buffers | < 1 GB |

---

## Implementation Phases

### Phase 1: Foundation
- Core types and data structures
- Cryptographic primitives
- Basic serialization (Borsh-compatible bincode)
- Unit test infrastructure

### Phase 2: Networking
- UDP socket layer
- Gossip protocol
- Contact info exchange
- Shred receiving (TVU)

### Phase 3: Storage
- AccountsDB implementation
- Blockstore implementation
- Snapshot loading
- Basic persistence

### Phase 4: Consensus
- Tower BFT implementation
- Vote processing
- Fork choice
- Leader schedule

### Phase 5: Runtime
- Bank implementation
- Native program implementations
- Transaction executor
- Replay stage

### Phase 6: BPF VM
- BPF interpreter
- Syscall implementations
- Program execution
- JIT compiler (optional)

### Phase 7: RPC & Integration
- JSON-RPC server
- WebSocket subscriptions
- Full validator integration
- Testnet participation

### Phase 8: Production Hardening
- Performance optimization
- Security audit
- Mainnet testing
- Documentation

---

## Appendix A: Serialization Format

Solana uses a Borsh-like binary format. Key rules:

- Little-endian byte order
- Fixed-size integers encoded as-is
- Variable-length arrays prefixed with u32 length
- Strings are UTF-8 with u32 length prefix
- Options encoded as u8 tag (0=None, 1=Some) followed by value
- Enums encoded as u8 variant index followed by variant data

---

## Appendix B: Key Constants

```c
#define SOL_LAMPORTS_PER_SOL          1000000000ULL
#define SOL_MAX_TX_SIZE               1232
#define SOL_MAX_ACCOUNTS_PER_TX       256
#define SOL_MAX_INSTRUCTION_DATA      1232
#define SOL_TICKS_PER_SLOT            64
#define SOL_NS_PER_SLOT               400000000  /* 400ms */
#define SOL_SLOTS_PER_EPOCH           432000
#define SOL_MAX_LOCKOUT_HISTORY       31
#define SOL_MAX_EPOCH_CREDITS_HISTORY 64
#define SOL_SHRED_VERSION             /* Cluster-specific */
```

---

## Appendix C: References

- [Solana Documentation](https://docs.solana.com/)
- [Solana Protocol Specification](https://docs.solana.com/developing/programming-model/overview)
- [Agave Validator Source](https://github.com/anza-xyz/agave)
- [Firedancer Implementation](https://github.com/firedancer-io/firedancer)
- [Tower BFT Paper](https://solana.com/solana-whitepaper.pdf)
- [QUIC RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
- [eBPF Specification](https://www.kernel.org/doc/html/latest/bpf/index.html)
