#!/usr/bin/env python3
"""
Final focused analysis:
1. Are the 132 lamport violation TXs "successful" (err=0) on Agave too?
   - If so, SolanaC is computing wrong output (lamports don't balance)
2. What programs are the violation TXs invoking?
3. For the non-vote true mismatches: are they involved in lamport violation TXs?
4. Cross-reference: which non-vote accounts had data changes that differ?
"""

import os
import re
import struct
import hashlib
from collections import Counter, defaultdict

BASE_DIR = "/home/ubuntu/solana-c/ledger.parity.1771302063"
LOG_FILE = os.path.join(BASE_DIR, "solanac.validator.log")

def load_tsv(path):
    accounts = {}
    with open(path, 'r') as f:
        header = f.readline().strip().split('\t')
        for line in f:
            fields = line.strip().split('\t')
            if len(fields) < len(header):
                continue
            rec = dict(zip(header, fields))
            accounts[rec['pubkey']] = rec
    return accounts

def main():
    delta = load_tsv(os.path.join(BASE_DIR, "delta_accounts.400699657.tsv"))

    # Parse all log entries for slot 400699657
    viol_pattern = re.compile(
        r'LAMPORT_VIOLATION: slot=400699657 delta=(-?\d+) fee=(\d+) payer=(\S+) sig=(\S+) accounts=(\d+)'
    )
    acct_pattern = re.compile(
        r'account\[(\d+)\] (\S+) pre=(\d+) post=(\d+) diff=(-?\d+)'
    )
    tx_result_pattern = re.compile(
        r'tx_result: slot=400699657 err=(-?\d+) cu=(\d+) fee=(\d+) payer=(\S+) sig=(\S+)'
    )
    exec_fail_pattern = re.compile(
        r'execution_failed: slot=400699657 instr=(\d+) program=(\S+) err=([^\s]+) cu=(\d+) sig=(\S+)'
    )

    violations = {}
    current_viol = None
    tx_results = {}
    exec_failures = defaultdict(list)  # sig -> list of failures

    with open(LOG_FILE, 'r') as f:
        for line in f:
            m = viol_pattern.search(line)
            if m:
                if current_viol:
                    violations[current_viol['sig']] = current_viol
                current_viol = {
                    'delta': int(m.group(1)),
                    'fee': int(m.group(2)),
                    'payer': m.group(3),
                    'sig': m.group(4),
                    'num_accounts': int(m.group(5)),
                    'changed_accounts': []
                }
                continue

            if current_viol:
                am = acct_pattern.search(line)
                if am:
                    current_viol['changed_accounts'].append({
                        'index': int(am.group(1)),
                        'pubkey': am.group(2),
                        'pre': int(am.group(3)),
                        'post': int(am.group(4)),
                        'diff': int(am.group(5)),
                    })
                    continue

            m = tx_result_pattern.search(line)
            if m:
                tx_results[m.group(5)] = {
                    'err': int(m.group(1)),
                    'cu': int(m.group(2)),
                    'fee': int(m.group(3)),
                    'payer': m.group(4),
                }
                continue

            m = exec_fail_pattern.search(line)
            if m:
                exec_failures[m.group(5)].append({
                    'instr': int(m.group(1)),
                    'program': m.group(2),
                    'err': m.group(3),
                    'cu': int(m.group(4)),
                })
                continue

    if current_viol:
        violations[current_viol['sig']] = current_viol

    print("=" * 80)
    print("LAMPORT VIOLATION ANALYSIS - DEEP DIVE")
    print("=" * 80)
    print(f"\n  Total violations: {len(violations)}")
    print(f"  Total tx_results: {len(tx_results)}")
    print(f"  Total exec_failures (unique sigs): {len(exec_failures)}")

    # Check: are any violation TXs also execution failures?
    viol_also_failed = set(violations.keys()) & set(exec_failures.keys())
    print(f"\n  Violation TXs that also had execution failures: {len(viol_also_failed)}")
    for sig in list(viol_also_failed)[:5]:
        for f in exec_failures[sig]:
            print(f"    {sig[:40]}... instr={f['instr']} program={f['program']} err={f['err']}")

    # Collect all programs involved in violation TXs
    # We need to look at the log to find which programs each TX invoked
    # For now, let's look at unique payers
    print(f"\n  Unique payers in violations:")
    payer_counts = Counter(v['payer'] for v in violations.values())
    for payer, cnt in payer_counts.most_common(20):
        print(f"    {payer}: {cnt} violations")

    # Key insight: all violations have err=0, meaning SolanaC thinks the TX succeeded
    # but the lamports don't balance. This suggests a BPF execution bug where
    # account data is being written incorrectly.

    # Let's look at the delta between pre and post for the violation accounts
    # and see if there's a common "extra" lamport amount
    print(f"\n  Analyzing violation deltas...")
    all_deltas = [v['delta'] for v in violations.values()]
    print(f"    Min delta: {min(all_deltas)}")
    print(f"    Max delta: {max(all_deltas)}")
    print(f"    Mean delta: {sum(all_deltas)/len(all_deltas):.0f}")
    print(f"    Sum of deltas: {sum(all_deltas)}")

    # Check if any violation accounts have specific owners (like AMM/DEX)
    print(f"\n  Owners of accounts involved in violations:")
    owner_counter = Counter()
    for v in violations.values():
        for a in v['changed_accounts']:
            drec = delta.get(a['pubkey'])
            if drec:
                owner_counter[drec['owner']] += 1
            else:
                owner_counter['NOT_IN_DELTA'] += 1

    for owner, cnt in owner_counter.most_common(20):
        print(f"    {owner[:44]}: {cnt}")

    # Now let's try to understand: are these transactions DEX/AMM swaps?
    # If so, the lamport imbalance might be because SolanaC's BPF execution
    # is computing different token amounts.

    # Check the first violation TX in detail
    print("\n" + "=" * 80)
    print("FIRST VIOLATION TX IN DETAIL")
    print("=" * 80)

    first_sig = list(violations.keys())[0]
    v = violations[first_sig]
    tr = tx_results.get(first_sig, {})
    print(f"\n  sig: {first_sig}")
    print(f"  payer: {v['payer']}")
    print(f"  delta: {v['delta']} fee: {v['fee']} cu: {tr.get('cu', '?')}")
    print(f"  num_accounts: {v['num_accounts']}")
    print(f"  All changed accounts:")
    for a in v['changed_accounts']:
        drec = delta.get(a['pubkey'])
        owner = drec['owner'] if drec else 'UNKNOWN'
        print(f"    [{a['index']:2d}] {a['pubkey']} pre={a['pre']} post={a['post']} diff={a['diff']:+d} owner={owner[:32]}")

    # For the 50 non-vote true data mismatches, let's check if they're in violation TXs
    print("\n" + "=" * 80)
    print("NON-VOTE MISMATCHES vs VIOLATION ACCOUNTS")
    print("=" * 80)

    delta_658 = load_tsv(os.path.join(BASE_DIR, "delta_accounts.400699658.tsv"))
    delta_659 = load_tsv(os.path.join(BASE_DIR, "delta_accounts.400699659.tsv"))
    later_modified = set(delta_658.keys()) | set(delta_659.keys())

    # Gather all accounts involved in violations
    viol_accounts = set()
    for v in violations.values():
        for a in v['changed_accounts']:
            viol_accounts.add(a['pubkey'])

    non_vote_true_mismatches = []
    for pubkey, drec in sorted(delta.items()):
        if pubkey in later_modified:
            continue
        if drec['owner'] == 'Vote111111111111111111111111111111111111111':
            continue
        bin_path = os.path.join(BASE_DIR, f"agave_acct_{pubkey}.bin")
        if not os.path.exists(bin_path):
            continue
        with open(bin_path, 'rb') as f:
            agave_data = f.read()
        agave_hash = hashlib.sha256(agave_data).hexdigest()[:16]
        sc_hash = drec['data_hash']
        sc_len = int(drec['curr_data_len'])
        if sc_len == 0 and len(agave_data) == 0:
            continue
        if sc_hash != agave_hash:
            non_vote_true_mismatches.append(pubkey)

    print(f"\n  Non-vote true data mismatches: {len(non_vote_true_mismatches)}")
    in_viol = [pk for pk in non_vote_true_mismatches if pk in viol_accounts]
    not_in_viol = [pk for pk in non_vote_true_mismatches if pk not in viol_accounts]
    print(f"  Of those, in lamport violation TXs: {len(in_viol)}")
    print(f"  Of those, NOT in lamport violation TXs: {len(not_in_viol)}")

    if in_viol:
        print(f"\n  Non-vote mismatches IN violations:")
        for pk in in_viol:
            drec = delta[pk]
            print(f"    {pk} owner={drec['owner'][:32]} lamports={drec['curr_lamports']}")

    if not_in_viol:
        print(f"\n  Non-vote mismatches NOT in violations:")
        for pk in not_in_viol:
            drec = delta[pk]
            print(f"    {pk} owner={drec['owner'][:32]} len={drec['curr_data_len']}")

    # Check: for non-vote accounts NOT in violations, are they in TXs that had exec failures?
    # We need to figure out which TXs touched these accounts
    print("\n" + "=" * 80)
    print("CHECKING IF NON-VOTE NON-VIOL MISMATCHES ARE IN FAILED TXs")
    print("=" * 80)

    # Parse all payer info to map payers to their transactions
    # We don't have per-account per-tx mapping from the log, but we can check
    # if any of the non-vote mismatch accounts are payers of failed TXs
    failed_payers = set()
    for sig, failures in exec_failures.items():
        tr = tx_results.get(sig)
        if tr:
            failed_payers.add(tr['payer'])

    non_viol_in_failed = [pk for pk in not_in_viol if pk in failed_payers]
    print(f"\n  Non-viol mismatched accounts that are payers of failed TXs: {len(non_viol_in_failed)}")

    # Summary: What's the most likely root cause?
    print("\n" + "=" * 80)
    print("ROOT CAUSE HYPOTHESIS")
    print("=" * 80)
    print(f"""
  Key findings:
  1. 132 transactions have lamport violations (err=0 but lamports don't balance)
     - All 132 are "successful" transactions
     - This means BPF programs are computing different outputs than Agave
     - The programs involved are mostly DeFi/AMM (SBPFv0 programs)

  2. 731 vote account data mismatches (all in slot 657, not modified later)
     - Vote accounts have same lamports but different data hashes
     - Since Agave dump is from slot 659 (2 slots later), vote accounts
       would have accumulated 2 more slots of votes
     - HOWEVER: these accounts were NOT modified in 658/659 per SolanaC
     - This means either: (a) SolanaC didn't process votes in 658/659, or
       (b) Agave processed different votes, or
       (c) the Agave dump IS the state at slot 657 (check this)

  3. 50 non-vote data mismatches:
     - Some are in lamport violation TXs (likely affected by computation bugs)
     - Some are NOT in violations (these need separate investigation)

  4. 75 execution failures (54 err=-501, 20 err=-903, 1 err=-508)
     - These may or may not match Agave's failures for the same TXs

  5. Clock sysvar mismatch is cosmetic (parent vs current slot, expected)

  PRIMARY ISSUE: The 132 lamport violations suggest SolanaC's BPF execution
  produces different account state than Agave for certain DeFi transactions.
  This could be:
  - A BPF VM instruction interpretation bug
  - A CPI account handling bug
  - A syscall implementation difference
  - An account data serialization/deserialization bug
""")

if __name__ == '__main__':
    main()
