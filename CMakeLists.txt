cmake_minimum_required(VERSION 3.20)

project(solana-c
    VERSION 0.1.0
    DESCRIPTION "Solana mainnet validator in pure C"
    LANGUAGES C
)

# Default build type (single-config generators)
#
# Without an explicit CMAKE_BUILD_TYPE, CMake's default is empty which results
# in unoptimized binaries. That is fine for some workflows, but it's a footgun
# for a validator where replay performance matters.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(SOLANA_C_DEFAULT_BUILD_TYPE "Release")
    message(STATUS "No build type selected, defaulting to ${SOLANA_C_DEFAULT_BUILD_TYPE}")
    set(CMAKE_BUILD_TYPE "${SOLANA_C_DEFAULT_BUILD_TYPE}" CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# C17 standard required
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Ensure static libs can be linked into shared objects (sol_compat)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# Export compile_commands.json for tooling
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include our CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(CompilerFlags)
include(Dependencies)
include(Testing)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Global include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Core utility library
add_library(sol_util STATIC
    src/util/sol_alloc.c
    src/util/sol_arena.c
    src/util/sol_config.c
    src/util/sol_crash.c
    src/util/sol_err.c
    src/util/sol_io.c
    src/util/sol_io_uring.c
    src/util/sol_json.c
    src/util/sol_log.c
    src/util/sol_map.c
    src/util/sol_rpc_client.c
    src/util/sol_slab.c
    src/util/sol_types.c
)

target_include_directories(sol_util PUBLIC
    ${CMAKE_SOURCE_DIR}/src/util
)

target_link_libraries(sol_util PUBLIC
    ${JEMALLOC_LIBRARIES}
    Threads::Threads
)

# Crypto library
add_library(sol_crypto STATIC
    src/crypto/sol_sha256.c
    src/crypto/sol_sha512.c
    src/crypto/sol_ed25519.c
    src/crypto/sol_blake3.c
    external/fd-src/src/ballet/blake3/fd_blake3.c
    external/fd-src/src/ballet/blake3/fd_blake3_ref.c
    external/fd-src/src/ballet/blake3/fd_blake3_sse41.c
    external/fd-src/src/ballet/blake3/fd_blake3_avx2.c
    src/crypto/sol_lt_hash.c
    src/crypto/sol_keccak256.c
    src/crypto/sol_secp256k1.c
)

target_include_directories(sol_crypto PUBLIC
    ${CMAKE_SOURCE_DIR}/src/crypto
    ${CMAKE_SOURCE_DIR}/external/fd-src/src/ballet
    ${SODIUM_INCLUDE_DIRS}
)

target_link_directories(sol_crypto PUBLIC
    ${SODIUM_LIBRARY_DIRS}
)

target_link_libraries(sol_crypto PUBLIC
    sol_util
    ${SODIUM_LIBRARIES}
)

if(SECP256K1_FOUND)
    target_include_directories(sol_crypto PUBLIC ${SECP256K1_INCLUDE_DIRS})
    target_link_directories(sol_crypto PUBLIC ${SECP256K1_LIBRARY_DIRS})
    target_link_libraries(sol_crypto PUBLIC ${SECP256K1_LIBRARIES})
    target_compile_definitions(sol_crypto PUBLIC SOL_HAS_SECP256K1=1)
endif()

if(SODIUM_FOUND)
    target_compile_definitions(sol_crypto PRIVATE SOL_USE_LIBSODIUM=1)
else()
    target_compile_definitions(sol_crypto PRIVATE SOL_USE_LIBSODIUM=0)
endif()

if(OPENSSL_FOUND)
    target_include_directories(sol_crypto PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(sol_crypto PUBLIC ${OPENSSL_LIBRARIES})
    target_compile_definitions(sol_crypto PUBLIC SOL_USE_OPENSSL=1)
else()
    target_compile_definitions(sol_crypto PUBLIC SOL_USE_OPENSSL=0)
endif()

# Transaction library (bincode, types, parsing)
add_library(sol_txn STATIC
    src/txn/sol_pubkey.c
    src/txn/sol_signature.c
    src/txn/sol_message.c
    src/txn/sol_transaction.c
)

target_include_directories(sol_txn PUBLIC
    ${CMAKE_SOURCE_DIR}/src/txn
)

target_link_libraries(sol_txn PUBLIC
    sol_util
    sol_crypto
)

# BPF VM library (sBPF virtual machine for on-chain programs)
add_library(sol_bpf STATIC
    src/bpf/sol_bpf_vm.c
    src/bpf/sol_bpf_syscall.c
    src/bpf/sol_bpf_elf.c
    src/bpf/sol_bpf_cpi.c
    src/bpf/sol_bpf_jit.c
    external/fd-src/src/ballet/bn254/fd_bn254.c
    external/fd-src/src/ballet/bn254/fd_poseidon.c
)

target_include_directories(sol_bpf PUBLIC
    ${CMAKE_SOURCE_DIR}/src/bpf
)

target_link_libraries(sol_bpf PUBLIC
    sol_util
    sol_crypto
    sol_txn
)

if(SODIUM_FOUND)
    target_compile_definitions(sol_bpf PRIVATE SOL_USE_LIBSODIUM=1)
else()
    target_compile_definitions(sol_bpf PRIVATE SOL_USE_LIBSODIUM=0)
endif()

# Network library (UDP, QUIC)
add_library(sol_net STATIC
    src/net/sol_udp.c
    src/net/sol_quic.c
)

target_include_directories(sol_net PUBLIC
    ${CMAKE_SOURCE_DIR}/src/net
)

target_link_libraries(sol_net PUBLIC
    sol_util
    Threads::Threads
)

# Link quiche if available
if(QUICHE_FOUND)
    if(QUICHE_INCLUDE_DIRS)
        target_include_directories(sol_net PUBLIC ${QUICHE_INCLUDE_DIRS})
    endif()
    target_link_libraries(sol_net PUBLIC ${QUICHE_LIBRARIES})
    target_compile_definitions(sol_net PUBLIC SOL_HAS_QUIC=1)
    message(STATUS "QUIC transport: enabled (quiche)")
else()
    message(STATUS "QUIC transport: disabled (quiche not found)")
endif()

# Gossip library (CRDS, protocol)
add_library(sol_gossip STATIC
    src/gossip/sol_crds.c
    src/gossip/sol_gossip_msg.c
    src/gossip/sol_gossip.c
)

target_include_directories(sol_gossip PUBLIC
    ${CMAKE_SOURCE_DIR}/src/gossip
)

target_link_libraries(sol_gossip PUBLIC
    sol_util
    sol_net
    sol_txn
    sol_crypto
)

# Shred library (block propagation)
add_library(sol_shred STATIC
    src/shred/sol_shred.c
)

target_include_directories(sol_shred PUBLIC
    ${CMAKE_SOURCE_DIR}/src/shred
)

target_link_libraries(sol_shred PUBLIC
    sol_util
    sol_txn
    sol_crypto
)

# Turbine library (block propagation)
add_library(sol_turbine STATIC
    src/turbine/sol_turbine.c
)

target_include_directories(sol_turbine PUBLIC
    ${CMAKE_SOURCE_DIR}/src/turbine
)

target_link_libraries(sol_turbine PUBLIC
    sol_util
    sol_net
    sol_shred
    sol_gossip
    sol_crypto
    sol_runtime
)

# Repair library (missing shred recovery)
add_library(sol_repair STATIC
    src/repair/sol_repair.c
)

target_include_directories(sol_repair PUBLIC
    ${CMAKE_SOURCE_DIR}/src/repair
)

target_link_libraries(sol_repair PUBLIC
    sol_util
    sol_net
    sol_shred
    sol_gossip
    sol_crypto
)

# Blockstore library (shred/block storage)
add_library(sol_blockstore STATIC
    src/blockstore/sol_blockstore.c
)

target_include_directories(sol_blockstore PUBLIC
    ${CMAKE_SOURCE_DIR}/src/blockstore
)

target_link_libraries(sol_blockstore PUBLIC
    sol_util
    sol_shred
    sol_gossip
    sol_entry
    sol_storage
)

# Entry library (block entries)
add_library(sol_entry STATIC
    src/entry/sol_entry.c
)

target_include_directories(sol_entry PUBLIC
    ${CMAKE_SOURCE_DIR}/src/entry
)

target_link_libraries(sol_entry PUBLIC
    sol_util
    sol_txn
    sol_crypto
)

# Storage library (pluggable backend with RocksDB support)
add_library(sol_storage STATIC
    src/storage/sol_storage_backend.c
    src/storage/sol_rocksdb.c
)

target_include_directories(sol_storage PUBLIC
    ${CMAKE_SOURCE_DIR}/src/storage
)

target_link_libraries(sol_storage PUBLIC
    sol_util
)

# Link RocksDB if available
if(ROCKSDB_FOUND)
    target_include_directories(sol_storage PUBLIC ${ROCKSDB_INCLUDE_DIRS})
    target_link_directories(sol_storage PUBLIC ${ROCKSDB_LIBRARY_DIRS})
    target_link_libraries(sol_storage PUBLIC ${ROCKSDB_LIBRARIES})
    target_compile_definitions(sol_storage PUBLIC SOL_HAS_ROCKSDB=1)
    message(STATUS "Storage backend: RocksDB enabled")
else()
    message(STATUS "Storage backend: Memory only (RocksDB not found)")
endif()

# Runtime library (accounts, bank, native programs)
add_library(sol_runtime STATIC
    src/runtime/sol_account.c
    src/runtime/sol_accounts_db.c
    src/runtime/sol_appendvec_index.c
    src/runtime/sol_accounts_hash.c
    src/runtime/sol_bank.c
    src/runtime/sol_compute_budget.c
    src/runtime/sol_leader_schedule.c
    src/runtime/sol_program.c
    src/runtime/sol_rewards.c
    src/runtime/sol_sysvar.c
    src/programs/sol_system_program.c
    src/programs/sol_vote_program.c
    src/programs/sol_stake_program.c
    src/programs/sol_address_lookup_table_program.c
    src/programs/sol_config_program.c
    src/programs/sol_token_program.c
    src/programs/sol_bpf_loader_program.c
    src/programs/sol_ed25519_program.c
    src/programs/sol_secp256k1_program.c
    src/programs/sol_secp256r1_program.c
)

target_include_directories(sol_runtime PUBLIC
    ${CMAKE_SOURCE_DIR}/src/runtime
    ${CMAKE_SOURCE_DIR}/src/programs
)

target_link_libraries(sol_runtime PUBLIC
    sol_util
    sol_txn
    sol_entry
    sol_crypto
    sol_storage
    sol_bpf
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(sol_runtime PUBLIC m)
endif()

if(SECP256K1_FOUND)
    target_include_directories(sol_runtime PUBLIC ${SECP256K1_INCLUDE_DIRS})
    target_link_directories(sol_runtime PUBLIC ${SECP256K1_LIBRARY_DIRS})
    target_link_libraries(sol_runtime PUBLIC ${SECP256K1_LIBRARIES})
    target_compile_definitions(sol_runtime PUBLIC SOL_HAS_SECP256K1=1)
endif()

# Programs library (kept for backward compatibility, links to runtime)
add_library(sol_programs INTERFACE)

target_link_libraries(sol_programs INTERFACE
    sol_runtime
)

# Replay library (bank forks, fork choice, replay stage)
add_library(sol_replay STATIC
    src/replay/sol_bank_forks.c
    src/replay/sol_fork_choice.c
    src/replay/sol_replay.c
)

target_include_directories(sol_replay PUBLIC
    ${CMAKE_SOURCE_DIR}/src/replay
)

target_link_libraries(sol_replay PUBLIC
    sol_util
    sol_runtime
    sol_blockstore
    sol_entry
    sol_crypto
)

# PoH library (proof of history, block production)
add_library(sol_poh STATIC
    src/poh/sol_poh.c
    src/poh/sol_block_producer.c
)

target_include_directories(sol_poh PUBLIC
    ${CMAKE_SOURCE_DIR}/src/poh
)

target_link_libraries(sol_poh PUBLIC
    sol_util
    sol_runtime
    sol_entry
    sol_crypto
)

# Snapshot library (state persistence)
add_library(sol_snapshot STATIC
    src/snapshot/sol_snapshot.c
    src/snapshot/sol_snapshot_archive.c
    src/snapshot/sol_snapshot_download.c
)

target_include_directories(sol_snapshot PUBLIC
    ${CMAKE_SOURCE_DIR}/src/snapshot
)

target_link_libraries(sol_snapshot PUBLIC
    sol_util
    sol_txn
    sol_runtime
    sol_crypto
)

# Add zstd support if available
if(ZSTD_FOUND)
    target_compile_definitions(sol_snapshot PUBLIC SOL_HAS_ZSTD=1)
    target_include_directories(sol_snapshot PUBLIC ${ZSTD_INCLUDE_DIRS})
    target_link_directories(sol_snapshot PUBLIC ${ZSTD_LIBRARY_DIRS})
    target_link_libraries(sol_snapshot PUBLIC ${ZSTD_LIBRARIES})
endif()

# Add lz4 support if available
if(LZ4_FOUND)
    target_compile_definitions(sol_snapshot PUBLIC SOL_HAS_LZ4=1)
    target_include_directories(sol_snapshot PUBLIC ${LZ4_INCLUDE_DIRS})
    target_link_directories(sol_snapshot PUBLIC ${LZ4_LIBRARY_DIRS})
    target_link_libraries(sol_snapshot PUBLIC ${LZ4_LIBRARIES})
endif()

# Consensus library (Tower BFT)
add_library(sol_consensus STATIC
    src/consensus/sol_tower.c
    src/consensus/sol_vote_tracker.c
    src/consensus/sol_vote_tx.c
)

target_include_directories(sol_consensus PUBLIC
    ${CMAKE_SOURCE_DIR}/src/consensus
)

target_link_libraries(sol_consensus PUBLIC
    sol_util
    sol_runtime
    sol_replay
    sol_crypto
)

# TPU library (transaction processing)
add_library(sol_tpu STATIC
    src/tpu/sol_tpu.c
    src/tpu/sol_sigverify.c
    src/tpu/sol_banking_stage.c
)

target_include_directories(sol_tpu PUBLIC
    ${CMAKE_SOURCE_DIR}/src/tpu
)

target_link_libraries(sol_tpu PUBLIC
    sol_util
    sol_net
    sol_txn
    sol_poh
    sol_runtime
    sol_crypto
)

# TVU library (transaction validation)
add_library(sol_tvu STATIC
    src/tvu/sol_tvu.c
)

target_include_directories(sol_tvu PUBLIC
    ${CMAKE_SOURCE_DIR}/src/tvu
)

target_link_libraries(sol_tvu PUBLIC
    sol_util
    sol_shred
    sol_blockstore
    sol_replay
    sol_turbine
    sol_repair
    sol_crypto
)

# RPC library (JSON-RPC server)
add_library(sol_rpc STATIC
    src/rpc/sol_rpc.c
    src/rpc/sol_health.c
)

target_include_directories(sol_rpc PUBLIC
    ${CMAKE_SOURCE_DIR}/src/rpc
)

target_link_libraries(sol_rpc PUBLIC
    sol_util
    sol_txn
    sol_runtime
    sol_replay
    sol_blockstore
    sol_crypto
)

# Metrics library (Prometheus exporter)
add_library(sol_metrics STATIC
    src/metrics/sol_prometheus.c
)

target_include_directories(sol_metrics PUBLIC
    ${CMAKE_SOURCE_DIR}/src/metrics
)

target_link_libraries(sol_metrics PUBLIC
    sol_util
    Threads::Threads
)

# Main validator executable
add_executable(solana-validator
    src/validator/main.c
)

target_link_libraries(solana-validator PRIVATE
    sol_rpc
    sol_metrics
    sol_tvu
    sol_tpu
    sol_snapshot
    sol_consensus
    sol_poh
    sol_replay
    sol_blockstore
    sol_repair
    sol_turbine
    sol_gossip
    sol_programs
    sol_runtime
    sol_entry
    sol_shred
    sol_txn
    sol_net
    sol_crypto
    sol_util
    ${SODIUM_LIBRARIES}
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Improve stack traces from sol_crash by exporting symbols.
    target_link_options(solana-validator PRIVATE "-rdynamic")
endif()

# CLI Tools
add_executable(sol-keygen
    src/tools/sol_keygen.c
)

target_include_directories(sol-keygen PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-keygen PRIVATE
    sol_txn
    sol_crypto
    sol_util
    ${SODIUM_LIBRARIES}
)

set_target_properties(sol-keygen PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(sol-vote
    src/tools/sol_vote_tool.c
)

target_include_directories(sol-vote PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-vote PRIVATE
    sol_programs
    sol_txn
    sol_crypto
    sol_util
    ${SODIUM_LIBRARIES}
)

set_target_properties(sol-vote PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(sol-entry-hash
    src/tools/sol_entry_hash_tool.c
)

target_include_directories(sol-entry-hash PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-entry-hash PRIVATE
    sol_blockstore
    sol_entry
    sol_runtime
    sol_txn
    sol_crypto
    sol_util
    ${SODIUM_LIBRARIES}
)

set_target_properties(sol-entry-hash PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(sol-slot-replay
    src/tools/sol_slot_replay_tool.c
)

target_include_directories(sol-slot-replay PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-slot-replay PRIVATE
    sol_blockstore
    sol_entry
    sol_snapshot
    sol_runtime
    sol_txn
    sol_crypto
    sol_util
    ${SODIUM_LIBRARIES}
)

set_target_properties(sol-slot-replay PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(sol-tx-decode
    src/tools/sol_tx_decode_tool.c
)

target_include_directories(sol-tx-decode PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-tx-decode PRIVATE
    sol_txn
    sol_util
)

set_target_properties(sol-tx-decode PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(sol-accounts-index
    src/tools/sol_accounts_index_tool.c
)

target_include_directories(sol-accounts-index PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-accounts-index PRIVATE
    sol_runtime
    sol_txn
    sol_crypto
    sol_util
    ${SODIUM_LIBRARIES}
)

set_target_properties(sol-accounts-index PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(sol-dump-sysvar
    src/tools/sol_dump_sysvar_tool.c
)

target_include_directories(sol-dump-sysvar PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-dump-sysvar PRIVATE
    sol_runtime
    sol_txn
    sol_crypto
    sol_util
    ${SODIUM_LIBRARIES}
)

set_target_properties(sol-dump-sysvar PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(sol-snapshot-fetch
    src/tools/sol_snapshot_fetch_tool.c
)

target_include_directories(sol-snapshot-fetch PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-snapshot-fetch PRIVATE
    sol_snapshot
    sol_util
)

set_target_properties(sol-snapshot-fetch PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(sol-dump-account
    src/tools/sol_dump_account_tool.c
)

target_include_directories(sol-dump-account PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-dump-account PRIVATE
    sol_runtime
    sol_txn
    sol_crypto
    sol_util
    ${SODIUM_LIBRARIES}
)

set_target_properties(sol-dump-account PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(sol-verify-vote-state
    src/tools/sol_verify_vote_state_tool.c
)

target_include_directories(sol-verify-vote-state PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol-verify-vote-state PRIVATE
    sol_runtime
    sol_txn
    sol_crypto
    sol_util
    ${SODIUM_LIBRARIES}
)

set_target_properties(sol-verify-vote-state PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Conformance harness shared library (for solana-conformance testing)
add_library(sol_compat SHARED
    src/conformance/sol_compat.c
)

target_include_directories(sol_compat PUBLIC
    ${CMAKE_SOURCE_DIR}/src/conformance
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sol_compat PUBLIC
    sol_runtime
    sol_txn
    sol_crypto
    sol_util
)

# Export all conformance symbols
set_target_properties(sol_compat PROPERTIES
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
)

# On macOS, use .dylib; on Linux, use .so
if(APPLE)
    set_target_properties(sol_compat PROPERTIES SUFFIX ".dylib")
else()
    set_target_properties(sol_compat PROPERTIES SUFFIX ".so")
endif()

# Tests
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# Benchmarks
option(BUILD_BENCHMARKS "Build benchmarks" OFF)
if(BUILD_BENCHMARKS)
    add_subdirectory(bench)
endif()

# Fuzzing
option(BUILD_FUZZERS "Build fuzz targets (libFuzzer)" OFF)
if(BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "=== solana-c configuration ===")
message(STATUS "Version:        ${PROJECT_VERSION}")
message(STATUS "Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler:     ${CMAKE_C_COMPILER}")
message(STATUS "C Flags:        ${CMAKE_C_FLAGS}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
