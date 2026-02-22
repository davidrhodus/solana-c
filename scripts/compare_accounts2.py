#!/usr/bin/env python3
"""
Deeper analysis:
1. Filter out accounts that were also modified in slots 658/659 (since Agave dump is from 659)
2. Examine the 132 lamport violations more closely
3. Look at sysvar mismatches
4. Identify truly divergent accounts (modified ONLY in slot 657, but hash differs)
"""

import os
import sys
import hashlib
from collections import defaultdict, Counter

BASE_DIR = "/home/ubuntu/solana-c/ledger.parity.1771302063"

KNOWN_PROGRAMS = {
    "11111111111111111111111111111111": "System Program",
    "Vote111111111111111111111111111111111111111": "Vote Program",
    "Stake11111111111111111111111111111111111111": "Stake Program",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "Token Program",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "Token-2022",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "Associated Token",
    "ComputeBudget111111111111111111111111111111": "Compute Budget",
    "BPFLoaderUpgradeab1e11111111111111111111111": "BPF Loader Upgradeable",
    "Sysvar1111111111111111111111111111111111111": "Sysvar",
}

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

def load_agave_binary_hash(pubkey):
    bin_path = os.path.join(BASE_DIR, f"agave_acct_{pubkey}.bin")
    if not os.path.exists(bin_path):
        return None, 0
    size = os.path.getsize(bin_path)
    with open(bin_path, 'rb') as f:
        data = f.read()
    h = hashlib.sha256(data).hexdigest()[:16]
    return h, size

def main():
    # Load all delta files
    delta_657 = load_tsv(os.path.join(BASE_DIR, "delta_accounts.400699657.tsv"))
    delta_658 = load_tsv(os.path.join(BASE_DIR, "delta_accounts.400699658.tsv"))
    delta_659 = load_tsv(os.path.join(BASE_DIR, "delta_accounts.400699659.tsv"))
    agave_tsv = load_tsv(os.path.join(BASE_DIR, "agave_accounts.tsv"))

    # Accounts modified in 658 or 659 (which would explain hash diff against Agave at 659)
    later_modified = set(delta_658.keys()) | set(delta_659.keys())

    print("=" * 80)
    print("DEEP ANALYSIS: Filtering accounts modified in later slots")
    print("=" * 80)
    print(f"\n  Delta 657 accounts: {len(delta_657)}")
    print(f"  Delta 658 accounts: {len(delta_658)}")
    print(f"  Delta 659 accounts: {len(delta_659)}")
    print(f"  Modified in 658 or 659: {len(later_modified)}")

    # Find accounts ONLY modified in 657 (not 658/659) that have hash mismatches
    only_657_mismatches = []
    only_657_matches = 0
    only_657_no_agave = 0

    for pubkey, drec in sorted(delta_657.items()):
        if pubkey in later_modified:
            continue  # Skip - modified later, hash diff expected

        agave_hash, agave_size = load_agave_binary_hash(pubkey)
        if agave_hash is None:
            only_657_no_agave += 1
            continue

        sc_hash = drec['data_hash']
        sc_len = int(drec['curr_data_len'])

        if sc_len == 0 and agave_size == 0:
            only_657_matches += 1
            continue

        if sc_hash == agave_hash:
            only_657_matches += 1
        else:
            owner = drec['owner']
            owner_name = KNOWN_PROGRAMS.get(owner, owner[:20] + "...")
            only_657_mismatches.append({
                'pubkey': pubkey,
                'owner': owner,
                'owner_name': owner_name,
                'sc_data_hash': sc_hash,
                'agave_data_hash': agave_hash,
                'sc_data_len': sc_len,
                'agave_data_len': agave_size,
                'sc_lamports': drec['curr_lamports'],
                'agave_lamports': agave_tsv.get(pubkey, {}).get('lamports', '?'),
            })

    print(f"\n  Accounts ONLY modified in 657 (not 658/659):")
    print(f"    Total: {len(delta_657) - len(set(delta_657.keys()) & later_modified)}")
    print(f"    Hash matches: {only_657_matches}")
    print(f"    Hash mismatches: {len(only_657_mismatches)}")
    print(f"    No agave binary: {only_657_no_agave}")

    if only_657_mismatches:
        owner_counts = Counter(m['owner_name'] for m in only_657_mismatches)
        print(f"\n  --- TRUE MISMATCHES (only mod in 657, hash differs) by owner ---")
        for owner_name, count in owner_counts.most_common():
            print(f"    {owner_name}: {count}")

        print(f"\n  --- Detailed TRUE MISMATCHES ---")
        for m in only_657_mismatches:
            print(f"  {m['pubkey']}")
            print(f"    owner={m['owner_name']} sc_len={m['sc_data_len']} agave_len={m['agave_data_len']}")
            print(f"    sc_hash={m['sc_data_hash']} agave_hash={m['agave_data_hash']}")
            print(f"    sc_lamports={m['sc_lamports']} agave_lamports={m['agave_lamports']}")

    # Check lamport comparison for true mismatches
    print("\n" + "=" * 80)
    print("LAMPORT COMPARISON for true mismatches")
    print("=" * 80)
    lamport_same = 0
    lamport_diff = 0
    for m in only_657_mismatches:
        if m['sc_lamports'] == m['agave_lamports']:
            lamport_same += 1
        else:
            lamport_diff += 1
    print(f"  Same lamports: {lamport_same}")
    print(f"  Different lamports: {lamport_diff}")

    # For sysvar accounts specifically
    print("\n" + "=" * 80)
    print("SYSVAR ACCOUNT ANALYSIS")
    print("=" * 80)

    sysvar_keys = [k for k in delta_657.keys() if k.startswith("Sysvar")]
    for sk in sorted(sysvar_keys):
        drec = delta_657[sk]
        agave_hash, agave_size = load_agave_binary_hash(sk)
        arec = agave_tsv.get(sk, {})
        in_later = sk in later_modified
        print(f"\n  {sk}")
        print(f"    In later slots: {in_later}")
        print(f"    sc_data_hash={drec['data_hash']} sc_len={drec['curr_data_len']}")
        print(f"    agave_bin_hash={agave_hash} agave_bin_len={agave_size}")
        if arec:
            print(f"    agave_tsv_hash={arec.get('data_hash','?')} agave_tsv_len={arec.get('data_len','?')}")
        print(f"    Hash match: {drec['data_hash'] == agave_hash if agave_hash else 'N/A'}")

    # Examine the lamport violations more closely
    print("\n" + "=" * 80)
    print("LAMPORT VIOLATION ANALYSIS")
    print("=" * 80)

    # Parse all lamport violations
    import re
    viol_pattern = re.compile(
        r'LAMPORT_VIOLATION: slot=400699657 delta=(-?\d+) fee=(\d+) payer=(\S+) sig=(\S+) accounts=(\d+)'
    )
    acct_pattern = re.compile(
        r'account\[(\d+)\] (\S+) pre=(\d+) post=(\d+) diff=(-?\d+)'
    )

    violations = []
    current_viol = None
    with open(os.path.join(BASE_DIR, "solanac.validator.log"), 'r') as f:
        for line in f:
            m = viol_pattern.search(line)
            if m:
                if current_viol:
                    violations.append(current_viol)
                current_viol = {
                    'delta': int(m.group(1)),
                    'fee': int(m.group(2)),
                    'payer': m.group(3),
                    'sig': m.group(4),
                    'num_accounts': int(m.group(5)),
                    'changed_accounts': []
                }
            elif current_viol:
                am = acct_pattern.search(line)
                if am:
                    current_viol['changed_accounts'].append({
                        'index': int(am.group(1)),
                        'pubkey': am.group(2),
                        'pre': int(am.group(3)),
                        'post': int(am.group(4)),
                        'diff': int(am.group(5)),
                    })
    if current_viol:
        violations.append(current_viol)

    print(f"\n  Total violations: {len(violations)}")

    # Analyze patterns in violations
    positive_deltas = [v for v in violations if v['delta'] > 0]
    negative_deltas = [v for v in violations if v['delta'] < 0]
    print(f"  Positive delta (more lamports out): {len(positive_deltas)}")
    print(f"  Negative delta (more lamports in):  {len(negative_deltas)}")

    # Check if certain accounts appear frequently in violations
    acct_freq = Counter()
    for v in violations:
        for a in v['changed_accounts']:
            acct_freq[a['pubkey']] += 1

    print(f"\n  Most frequent accounts in violations:")
    for pk, cnt in acct_freq.most_common(20):
        owner = delta_657.get(pk, {}).get('owner', 'unknown')
        owner_name = KNOWN_PROGRAMS.get(owner, owner[:20] + "...")
        print(f"    {pk} ({cnt}x) owner={owner_name}")

    # Check: do violations always involve the same "culprit" accounts?
    # Look for accounts that appear with LARGE diffs
    large_diff_accts = Counter()
    for v in violations:
        for a in v['changed_accounts']:
            if abs(a['diff']) > 1000000:  # > 0.001 SOL
                large_diff_accts[a['pubkey']] += 1

    print(f"\n  Accounts with large diffs (>1M lamports) in violations:")
    for pk, cnt in large_diff_accts.most_common(20):
        owner = delta_657.get(pk, {}).get('owner', 'unknown')
        owner_name = KNOWN_PROGRAMS.get(owner, owner[:20] + "...")
        # Get total diff across all violations
        total_diff = sum(a['diff'] for v in violations for a in v['changed_accounts'] if a['pubkey'] == pk)
        print(f"    {pk} ({cnt}x) total_diff={total_diff} owner={owner_name}")

    # Check delta sums
    print(f"\n  Sum of all deltas: {sum(v['delta'] for v in violations)}")
    print(f"  Sum of all fees:   {sum(v['fee'] for v in violations)}")

    # Look for common patterns - do all violations involve similar programs?
    # Check the tx_result lines for violation signatures
    print("\n" + "=" * 80)
    print("TX RESULTS FOR LAMPORT VIOLATION TRANSACTIONS")
    print("=" * 80)

    tx_result_pattern = re.compile(
        r'tx_result: slot=400699657 err=(\S+) cu=(\d+) fee=(\d+) payer=(\S+) sig=(\S+)'
    )
    tx_results = {}
    with open(os.path.join(BASE_DIR, "solanac.validator.log"), 'r') as f:
        for line in f:
            m = tx_result_pattern.search(line)
            if m:
                tx_results[m.group(5)] = {
                    'err': m.group(1),
                    'cu': int(m.group(2)),
                    'fee': int(m.group(3)),
                    'payer': m.group(4),
                }

    # Match violations to tx results
    viol_with_result = 0
    viol_err_counts = Counter()
    for v in violations:
        tr = tx_results.get(v['sig'])
        if tr:
            viol_with_result += 1
            viol_err_counts[tr['err']] += 1

    print(f"\n  Violations with tx_result: {viol_with_result}/{len(violations)}")
    print(f"  Error distribution:")
    for err, cnt in viol_err_counts.most_common():
        print(f"    {err}: {cnt}")

    # Show a few specific violation tx results
    print(f"\n  First 5 violation tx details:")
    for v in violations[:5]:
        tr = tx_results.get(v['sig'], {})
        print(f"  sig={v['sig'][:40]}...")
        print(f"    delta={v['delta']} fee={v['fee']} err={tr.get('err','?')} cu={tr.get('cu','?')}")
        for a in v['changed_accounts'][:5]:
            print(f"    acct[{a['index']}] {a['pubkey']} diff={a['diff']}")

    # Now check if account 62qc2CNXwrYqQScmEdiZFFAnJR262PxWEuNQtxfafNgV appears a lot
    # This was seen in several violations
    print("\n" + "=" * 80)
    print("FREQUENT VIOLATION ACCOUNT: 62qc2CNXwrYqQScmEdiZFFAnJR262PxWEuNQtxfafNgV")
    print("=" * 80)

    pk = "62qc2CNXwrYqQScmEdiZFFAnJR262PxWEuNQtxfafNgV"
    if pk in delta_657:
        drec = delta_657[pk]
        print(f"  In delta 657: yes")
        print(f"  Owner: {drec['owner']}")
        print(f"  Prev lamports: {drec['prev_lamports']}")
        print(f"  Curr lamports: {drec['curr_lamports']}")
        print(f"  Data len: {drec['curr_data_len']}")
        print(f"  Data hash: {drec['data_hash']}")
    else:
        print(f"  Not in delta 657")

    # Count appearances
    appearances = []
    for v in violations:
        for a in v['changed_accounts']:
            if a['pubkey'] == pk:
                appearances.append((v['sig'], a['diff']))

    print(f"  Appears in {len(appearances)} violations")
    if appearances:
        diffs = [a[1] for a in appearances]
        print(f"  Diff values: min={min(diffs)} max={max(diffs)} all_same={len(set(diffs))==1}")
        if len(set(diffs)) <= 5:
            for d, cnt in Counter(diffs).most_common():
                print(f"    diff={d}: {cnt} times")

if __name__ == '__main__':
    main()
