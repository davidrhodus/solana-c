#!/usr/bin/env python3
"""Compare SolanaC tx results against mainnet for slot 401587774."""
import sys, json, re, requests

MAINNET_RPC = "https://api.mainnet-beta.solana.com"
SOLANAC_LOG = sys.argv[1] if len(sys.argv) > 1 else "ledger.parity.500/solanac.delta.log"
SLOT = 401587774

def get_block_mainnet():
    payload = {
        "jsonrpc": "2.0", "id": 1,
        "method": "getBlock",
        "params": [SLOT, {"encoding": "json", "transactionDetails": "full",
                          "maxSupportedTransactionVersion": 0}]
    }
    resp = requests.post(MAINNET_RPC, json=payload, timeout=60)
    return resp.json()["result"]

def parse_solanac_failures(log_path, slot):
    """Parse execution_failed lines for the given slot."""
    failures = {}
    pattern = re.compile(r'execution_failed: slot=(\d+) instr=(\d+) program=(\S+) err=(-?\d+)\(([^)]*)\) cu=(\d+) sig=(\S+)')
    with open(log_path) as f:
        for line in f:
            m = pattern.search(line)
            if m and int(m.group(1)) == slot:
                sig = m.group(7)
                failures[sig] = {
                    'instr': int(m.group(2)),
                    'program': m.group(3),
                    'err': int(m.group(4)),
                    'err_msg': m.group(5),
                    'cu': int(m.group(6)),
                }
    return failures

def main():
    print(f"Parsing SolanaC failures for slot {SLOT}...")
    sc_failures = parse_solanac_failures(SOLANAC_LOG, SLOT)
    print(f"SolanaC failures: {len(sc_failures)}")

    print(f"Fetching mainnet block for slot {SLOT}...")
    block = get_block_mainnet()
    txs = block["transactions"]
    print(f"Mainnet transactions: {len(txs)}")

    mainnet_failures = {}
    mainnet_successes = {}
    for i, tx in enumerate(txs):
        sig = tx["transaction"]["signatures"][0]
        err = tx.get("meta", {}).get("err")
        if err is not None:
            mainnet_failures[sig] = err
        else:
            mainnet_successes[sig] = i

    print(f"Mainnet failures: {len(mainnet_failures)}")
    print(f"Mainnet successes: {len(mainnet_successes)}")

    # Find discrepancies
    # Case 1: SolanaC failed but mainnet succeeded
    sc_fail_mainnet_ok = []
    for sig, info in sc_failures.items():
        if sig in mainnet_successes:
            sc_fail_mainnet_ok.append((sig, info, mainnet_successes[sig]))

    # Case 2: Mainnet failed but SolanaC succeeded (SolanaC has no record of the failure)
    mainnet_fail_sc_ok = []
    for sig, err in mainnet_failures.items():
        if sig not in sc_failures:
            mainnet_fail_sc_ok.append((sig, err))

    print(f"\n=== SolanaC FAILED but mainnet SUCCEEDED: {len(sc_fail_mainnet_ok)} ===")
    for sig, info, tx_idx in sc_fail_mainnet_ok[:20]:
        print(f"  TX#{tx_idx} sig={sig}")
        print(f"    SC: instr={info['instr']} program={info['program']} err={info['err']}({info['err_msg']}) cu={info['cu']}")

    print(f"\n=== Mainnet FAILED but SolanaC SUCCEEDED: {len(mainnet_fail_sc_ok)} ===")
    for sig, err in mainnet_fail_sc_ok[:20]:
        print(f"  sig={sig} mainnet_err={err}")

    # Case 3: Both failed but different error
    both_fail_diff = []
    for sig, info in sc_failures.items():
        if sig in mainnet_failures:
            pass  # Both failed, OK

    print(f"\n=== Both failed (same result): {len(sc_failures) - len(sc_fail_mainnet_ok)} ===")
    print(f"=== Mainnet failures not in SolanaC: {len(mainnet_fail_sc_ok)} ===")

if __name__ == "__main__":
    main()
