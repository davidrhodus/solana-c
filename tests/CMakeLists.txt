# tests/CMakeLists.txt - Test configuration

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Unit tests
sol_add_unit_test(util
    SOURCES unit/test_util.c
    LIBS sol_util
)

# Config parser unit tests
sol_add_unit_test(config
    SOURCES unit/test_config.c
    LIBS sol_util
)

# Crypto unit tests
sol_add_unit_test(crypto
    SOURCES unit/test_crypto.c
    LIBS sol_crypto sol_util
)

# Transaction unit tests
sol_add_unit_test(txn
    SOURCES unit/test_txn.c
    LIBS sol_txn sol_util
)

# Network unit tests
sol_add_unit_test(net
    SOURCES unit/test_net.c
    LIBS sol_net sol_util
)

# Gossip unit tests
sol_add_unit_test(gossip
    SOURCES unit/test_gossip.c
    LIBS sol_gossip sol_net sol_util
)

# Shred unit tests
sol_add_unit_test(shred
    SOURCES unit/test_shred.c
    LIBS sol_shred sol_crypto sol_util
)

# Turbine unit tests
sol_add_unit_test(turbine
    SOURCES unit/test_turbine.c
    LIBS sol_turbine sol_shred sol_gossip sol_net sol_crypto sol_util
)

# Repair unit tests
sol_add_unit_test(repair
    SOURCES unit/test_repair.c
    LIBS sol_repair sol_blockstore sol_turbine sol_shred sol_gossip sol_net sol_crypto sol_util
)

# Blockstore unit tests
sol_add_unit_test(blockstore
    SOURCES unit/test_blockstore.c
    LIBS sol_blockstore sol_shred sol_gossip sol_net sol_crypto sol_util
)

# Entry unit tests
sol_add_unit_test(entry
    SOURCES unit/test_entry.c
    LIBS sol_entry sol_txn sol_crypto sol_util
)

# Runtime unit tests
sol_add_unit_test(runtime
    SOURCES unit/test_runtime.c
    LIBS sol_runtime sol_entry sol_txn sol_crypto sol_util
)

# Replay unit tests
sol_add_unit_test(replay
    SOURCES unit/test_replay.c
    LIBS sol_replay sol_runtime sol_blockstore sol_entry sol_txn sol_crypto sol_util
)

# Fork choice unit tests
sol_add_unit_test(fork_choice
    SOURCES unit/test_fork_choice.c
    LIBS sol_replay sol_runtime sol_blockstore sol_entry sol_txn sol_crypto sol_util
)

# Programs unit tests
sol_add_unit_test(programs
    SOURCES unit/test_programs.c
    LIBS sol_programs sol_runtime sol_entry sol_txn sol_crypto sol_util
)

# PoH unit tests
sol_add_unit_test(poh
    SOURCES unit/test_poh.c
    LIBS sol_poh sol_runtime sol_entry sol_txn sol_crypto sol_util
)

# Snapshot unit tests
sol_add_unit_test(snapshot
    SOURCES unit/test_snapshot.c
    LIBS sol_snapshot sol_runtime sol_txn sol_crypto sol_util
)

# TPU unit tests
sol_add_unit_test(tpu
    SOURCES unit/test_tpu.c
    LIBS sol_tpu sol_runtime sol_poh sol_crypto sol_util
)

# TVU unit tests
sol_add_unit_test(tvu
    SOURCES unit/test_tvu.c
    LIBS sol_tvu sol_blockstore sol_replay sol_runtime sol_shred sol_crypto sol_util
)

# Block production integration-ish tests
sol_add_unit_test(block_production
    SOURCES unit/test_block_production.c
    LIBS sol_poh sol_tvu sol_replay sol_runtime sol_blockstore sol_shred sol_crypto sol_txn sol_util
)

# Consensus (Tower BFT) unit tests
sol_add_unit_test(consensus
    SOURCES unit/test_consensus.c
    LIBS sol_consensus sol_replay sol_runtime sol_crypto sol_util
)

# RPC unit tests
sol_add_unit_test(rpc
    SOURCES unit/test_rpc.c
    LIBS sol_rpc sol_replay sol_runtime sol_crypto sol_util
)

# Vote Tracker unit tests
sol_add_unit_test(vote_tracker
    SOURCES unit/test_vote_tracker.c
    LIBS sol_consensus sol_programs sol_runtime sol_crypto sol_util
)

# Sysvar, AccountsHash, Rewards unit tests
sol_add_unit_test(sysvar
    SOURCES unit/test_sysvar.c
    LIBS sol_runtime sol_crypto sol_util
)

# BPF VM unit tests
sol_add_unit_test(bpf
    SOURCES unit/test_bpf.c
    LIBS sol_bpf sol_runtime sol_txn sol_crypto sol_util
)

# Integration tests (placeholder)
# sol_add_integration_test(gossip
#     SOURCES integration/test_gossip.c
#     LIBS sol_net sol_util
#     TIMEOUT 120
# )

# Conformance harness library
add_library(sol_conformance STATIC
    conformance/conformance.c
)
target_include_directories(sol_conformance PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/conformance
    ${CMAKE_SOURCE_DIR}/src/util
    ${CMAKE_SOURCE_DIR}/src/txn
    ${CMAKE_SOURCE_DIR}/src/runtime
    ${CMAKE_SOURCE_DIR}/src/shred
    ${CMAKE_SOURCE_DIR}/src/crypto
)
target_link_libraries(sol_conformance
    sol_runtime
    sol_shred
    sol_txn
    sol_crypto
    sol_util
)

# Conformance test runner
add_executable(test_conformance
    conformance/test_conformance.c
)
target_link_libraries(test_conformance
    sol_conformance
    sol_replay
    sol_runtime
    sol_shred
    sol_txn
    sol_crypto
    sol_util
)
target_include_directories(test_conformance PRIVATE
    ${CMAKE_SOURCE_DIR}/src/replay
)
set_target_properties(test_conformance PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
)

# Create fixtures directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/conformance/fixtures)

# Add conformance test to CTest (will skip if no fixtures)
add_test(NAME conformance_all
    COMMAND test_conformance -v ${CMAKE_CURRENT_SOURCE_DIR}/conformance/fixtures all
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# Always run built-in selftests (no fixtures required)
add_test(NAME conformance_selftest
    COMMAND test_conformance selftest
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# RPC conformance (HTTP-level)
add_executable(test_rpc_conformance
    conformance/test_rpc_conformance.c
)
target_link_libraries(test_rpc_conformance
    sol_rpc
    sol_replay
    sol_runtime
    sol_blockstore
    sol_shred
    sol_txn
    sol_crypto
    sol_util
)
set_target_properties(test_rpc_conformance PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
)
add_test(NAME conformance_rpc
    COMMAND test_rpc_conformance
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
