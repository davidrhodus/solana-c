# fuzz/CMakeLists.txt - libFuzzer targets

include_directories(${CMAKE_SOURCE_DIR}/src)

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Fuzzers require Clang (libFuzzer via -fsanitize=fuzzer)")
endif()

set(SOL_FUZZ_SANITIZERS "-fsanitize=fuzzer,address,undefined")

function(sol_add_fuzzer name)
    set(options "")
    set(oneValueArgs "")
    set(multiValueArgs SOURCES LIBS)
    cmake_parse_arguments(FUZZ "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    add_executable(fuzz_${name} ${FUZZ_SOURCES})
    target_link_libraries(fuzz_${name} PRIVATE ${FUZZ_LIBS})

    target_compile_options(fuzz_${name} PRIVATE ${SOL_FUZZ_SANITIZERS})
    target_link_options(fuzz_${name} PRIVATE ${SOL_FUZZ_SANITIZERS})
endfunction()

sol_add_fuzzer(transaction_decode
    SOURCES fuzz_transaction_decode.c
    LIBS sol_txn sol_crypto sol_util
)

sol_add_fuzzer(shred_parse
    SOURCES fuzz_shred_parse.c
    LIBS sol_shred sol_crypto sol_txn sol_util
)

sol_add_fuzzer(gossip_msg_decode
    SOURCES fuzz_gossip_msg_decode.c
    LIBS sol_gossip sol_net sol_txn sol_util
)

sol_add_fuzzer(config_parse
    SOURCES fuzz_config_parse.c
    LIBS sol_util
)

sol_add_fuzzer(pubkey_base58
    SOURCES fuzz_pubkey_base58.c
    LIBS sol_txn sol_util
)

sol_add_fuzzer(signature_base58
    SOURCES fuzz_signature_base58.c
    LIBS sol_txn sol_util
)

sol_add_fuzzer(json_parser
    SOURCES fuzz_json_parser.c
    LIBS sol_rpc sol_util
)

sol_add_fuzzer(entry_batch_parse
    SOURCES fuzz_entry_batch_parse.c
    LIBS sol_entry sol_txn sol_crypto sol_util
)

sol_add_fuzzer(compute_budget_parse
    SOURCES fuzz_compute_budget_parse.c
    LIBS sol_runtime sol_txn sol_crypto sol_util
)

sol_add_fuzzer(rpc_handle_request_json
    SOURCES fuzz_rpc_handle_request_json.c
    LIBS sol_rpc sol_runtime sol_txn sol_crypto sol_util
)

sol_add_fuzzer(blockstore_insert
    SOURCES fuzz_blockstore_insert.c
    LIBS sol_blockstore sol_shred sol_entry sol_crypto sol_util
)

sol_add_fuzzer(snapshot_service_manifest_json
    SOURCES fuzz_snapshot_service_manifest_json.c
    LIBS sol_snapshot
)

sol_add_fuzzer(snapshot_filename_parse
    SOURCES fuzz_snapshot_filename_parse.c
    LIBS sol_snapshot
)
