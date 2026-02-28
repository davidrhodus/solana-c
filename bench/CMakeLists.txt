# bench/CMakeLists.txt - Benchmark configuration

include_directories(${CMAKE_SOURCE_DIR}/src)

add_executable(bench_ed25519
    bench_ed25519.c
)
target_link_libraries(bench_ed25519 PRIVATE
    sol_crypto
    sol_util
)

add_executable(bench_shred
    bench_shred.c
)
target_link_libraries(bench_shred PRIVATE
    sol_shred
    sol_crypto
    sol_txn
    sol_util
)

add_executable(bench_accounts
    bench_accounts.c
)
target_link_libraries(bench_accounts PRIVATE
    sol_runtime
    sol_crypto
    sol_txn
    sol_util
)

add_executable(bench_poh
    bench_poh.c
)
target_link_libraries(bench_poh PRIVATE
    sol_crypto
    sol_util
)

add_executable(bench_entry_verify
    bench_entry_verify.c
)
target_link_libraries(bench_entry_verify PRIVATE
    sol_blockstore
    sol_entry
    sol_txn
    sol_crypto
    sol_util
)
