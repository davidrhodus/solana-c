#!/usr/bin/env python3
"""
Compare SolanaC delta accounts for slot 400699657 against Agave account dumps.
Focus on data_hash differences (not lamports, since Agave TSV is from a later slot).
"""

import os
import sys
import hashlib
import re
from collections import defaultdict, Counter

BASE_DIR = "/home/ubuntu/solana-c/ledger.parity.1771302063"
DELTA_FILE = os.path.join(BASE_DIR, "delta_accounts.400699657.tsv")
AGAVE_TSV = os.path.join(BASE_DIR, "agave_accounts.tsv")
LOG_FILE = os.path.join(BASE_DIR, "solanac.validator.log")

# Known program IDs and their names
KNOWN_PROGRAMS = {
    "11111111111111111111111111111111": "System Program",
    "Vote111111111111111111111111111111111111111": "Vote Program",
    "Stake11111111111111111111111111111111111111": "Stake Program",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "Token Program",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "Token-2022",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "Associated Token",
    "ComputeBudget111111111111111111111111111111": "Compute Budget",
    "BPFLoaderUpgradeab1e11111111111111111111111": "BPF Loader Upgradeable",
    "BPFLoader2111111111111111111111111111111111": "BPF Loader v2",
    "AddressLookupTab1e1111111111111111111111111": "Address Lookup Table",
    "Config1111111111111111111111111111111111111": "Config Program",
}

def load_delta_accounts():
    """Load SolanaC delta accounts TSV."""
    accounts = {}
    with open(DELTA_FILE, 'r') as f:
        header = f.readline().strip().split('\t')
        for line in f:
            fields = line.strip().split('\t')
            if len(fields) < len(header):
                continue
            rec = dict(zip(header, fields))
            accounts[rec['pubkey']] = rec
    return accounts

def load_agave_accounts():
    """Load Agave accounts TSV."""
    accounts = {}
    with open(AGAVE_TSV, 'r') as f:
        header = f.readline().strip().split('\t')
        for line in f:
            fields = line.strip().split('\t')
            if len(fields) < len(header):
                continue
            rec = dict(zip(header, fields))
            accounts[rec['pubkey']] = rec
    return accounts

def compute_data_hash_hex(data: bytes) -> str:
    """Compute the first 8 bytes of SHA256 as hex (matching the TSV format)."""
    h = hashlib.sha256(data).hexdigest()[:16]
    return h

def load_agave_binary_hash(pubkey):
    """Load Agave binary dump and compute data hash."""
    bin_path = os.path.join(BASE_DIR, f"agave_acct_{pubkey}.bin")
    if not os.path.exists(bin_path):
        return None, None, 0
    size = os.path.getsize(bin_path)
    if size == 0:
        # Empty file means 0-length data
        h = hashlib.sha256(b'').hexdigest()[:16]
        return h, b'', 0
    with open(bin_path, 'rb') as f:
        data = f.read()
    h = hashlib.sha256(data).hexdigest()[:16]
    return h, data, size

def parse_execution_failures(slot):
    """Parse execution failures from log for given slot."""
    failures = []
    pattern = re.compile(
        r'execution_failed: slot=(\d+) instr=(\d+) program=(\S+) err=([^\s]+) cu=(\d+) sig=(\S+)'
    )
    with open(LOG_FILE, 'r') as f:
        for line in f:
            m = pattern.search(line)
            if m and m.group(1) == str(slot):
                failures.append({
                    'instr': int(m.group(2)),
                    'program': m.group(3),
                    'err': m.group(4),
                    'cu': int(m.group(5)),
                    'sig': m.group(6),
                })
    return failures

def parse_lamport_violations(slot):
    """Parse lamport violations from log for given slot."""
    violations = []
    viol_pattern = re.compile(
        r'LAMPORT_VIOLATION: slot=(\d+) delta=(-?\d+) fee=(\d+) payer=(\S+) sig=(\S+) accounts=(\d+)'
    )
    acct_pattern = re.compile(
        r'account\[(\d+)\] (\S+) pre=(\d+) post=(\d+) diff=(-?\d+)'
    )
    current_viol = None
    with open(LOG_FILE, 'r') as f:
        for line in f:
            m = viol_pattern.search(line)
            if m and m.group(1) == str(slot):
                if current_viol:
                    violations.append(current_viol)
                current_viol = {
                    'delta': int(m.group(2)),
                    'fee': int(m.group(3)),
                    'payer': m.group(4),
                    'sig': m.group(5),
                    'num_accounts': int(m.group(6)),
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
                elif 'LAMPORT_VIOLATION' not in line and 'account[' not in line:
                    # End of this violation's account list
                    pass
    if current_viol:
        violations.append(current_viol)
    return violations

def main():
    print("=" * 80)
    print("ACCOUNT STATE COMPARISON: SolanaC vs Agave for slot 400699657")
    print("=" * 80)

    # Load data
    print("\nLoading delta accounts...")
    delta = load_delta_accounts()
    print(f"  SolanaC delta accounts: {len(delta)}")

    print("Loading Agave accounts...")
    agave = load_agave_accounts()
    print(f"  Agave accounts (final state): {len(agave)}")

    # Count agave binary dumps
    bin_count = 0
    for f in os.listdir(BASE_DIR):
        if f.startswith("agave_acct_") and f.endswith(".bin"):
            bin_count += 1
    print(f"  Agave binary dumps: {bin_count}")

    # ---- Analysis 1: Data hash comparison ----
    print("\n" + "=" * 80)
    print("ANALYSIS 1: Data Hash Comparison (SolanaC curr vs Agave binary dump)")
    print("=" * 80)

    data_hash_match = 0
    data_hash_mismatch = 0
    data_hash_missing_bin = 0
    mismatches = []
    owner_mismatch_counts = Counter()

    for pubkey, drec in sorted(delta.items()):
        agave_hash, agave_data, agave_size = load_agave_binary_hash(pubkey)
        agave_tsv = agave.get(pubkey)

        if agave_hash is None:
            data_hash_missing_bin += 1
            continue

        sc_data_hash = drec['data_hash']
        sc_data_len = int(drec['curr_data_len'])

        # Compare data hashes
        # SolanaC uses 0000000000000000 for empty data
        if sc_data_len == 0 and agave_size == 0:
            data_hash_match += 1
            continue

        if sc_data_hash == agave_hash:
            data_hash_match += 1
        else:
            data_hash_mismatch += 1
            owner = drec['owner']
            owner_name = KNOWN_PROGRAMS.get(owner, owner[:16] + "...")
            mismatches.append({
                'pubkey': pubkey,
                'owner': owner,
                'owner_name': owner_name,
                'sc_data_hash': sc_data_hash,
                'agave_data_hash': agave_hash,
                'sc_data_len': sc_data_len,
                'agave_data_len': agave_size,
                'type': drec['type'],
                'executable': drec['executable'],
            })
            owner_mismatch_counts[owner_name] += 1

    print(f"\n  Data hash matches:   {data_hash_match}")
    print(f"  Data hash mismatches: {data_hash_mismatch}")
    print(f"  Missing binary dump:  {data_hash_missing_bin}")

    if mismatches:
        print(f"\n  --- Data Hash Mismatches by Owner ---")
        for owner_name, count in owner_mismatch_counts.most_common():
            print(f"    {owner_name}: {count}")

        print(f"\n  --- Detailed Mismatches (first 50) ---")
        for i, m in enumerate(mismatches[:50]):
            print(f"  [{i+1}] {m['pubkey']}")
            print(f"       owner={m['owner_name']} data_len(sc={m['sc_data_len']}, agave={m['agave_data_len']}) exec={m['executable']} type={m['type']}")
            print(f"       sc_hash={m['sc_data_hash']}  agave_hash={m['agave_data_hash']}")

    # ---- Analysis 2: Data length mismatches ----
    print("\n" + "=" * 80)
    print("ANALYSIS 2: Data Length Comparison")
    print("=" * 80)

    len_mismatches = [m for m in mismatches if m['sc_data_len'] != m['agave_data_len']]
    len_same_hash_diff = [m for m in mismatches if m['sc_data_len'] == m['agave_data_len']]

    print(f"\n  Data length differs:  {len(len_mismatches)}")
    print(f"  Same length, different hash: {len(len_same_hash_diff)}")

    if len_mismatches:
        print("\n  --- Length Mismatches ---")
        for m in len_mismatches[:20]:
            print(f"    {m['pubkey']} sc_len={m['sc_data_len']} agave_len={m['agave_data_len']} owner={m['owner_name']}")

    # ---- Analysis 3: Agave TSV comparison ----
    print("\n" + "=" * 80)
    print("ANALYSIS 3: Agave TSV Data Hash Comparison")
    print("(NOTE: Agave TSV is from a LATER slot, so lamports may differ)")
    print("=" * 80)

    tsv_hash_match = 0
    tsv_hash_mismatch = 0
    tsv_missing = 0
    tsv_mismatches = []

    for pubkey, drec in sorted(delta.items()):
        arec = agave.get(pubkey)
        if arec is None:
            tsv_missing += 1
            continue

        sc_hash = drec['data_hash']
        agave_hash = arec['data_hash']
        sc_data_len = int(drec['curr_data_len'])
        agave_data_len = int(arec['data_len'])

        # Empty data special case
        if sc_data_len == 0 and agave_data_len == 0:
            tsv_hash_match += 1
            continue

        if sc_hash == agave_hash:
            tsv_hash_match += 1
        else:
            tsv_hash_mismatch += 1
            owner = drec['owner']
            owner_name = KNOWN_PROGRAMS.get(owner, owner[:16] + "...")
            tsv_mismatches.append({
                'pubkey': pubkey,
                'owner': owner,
                'owner_name': owner_name,
                'sc_data_hash': sc_hash,
                'agave_data_hash': agave_hash,
                'sc_data_len': sc_data_len,
                'agave_data_len': agave_data_len,
            })

    print(f"\n  TSV hash matches:   {tsv_hash_match}")
    print(f"  TSV hash mismatches: {tsv_hash_mismatch}")
    print(f"  Not in Agave TSV:    {tsv_missing}")

    if tsv_mismatches:
        tsv_owner_counts = Counter(m['owner_name'] for m in tsv_mismatches)
        print(f"\n  --- TSV Hash Mismatches by Owner ---")
        for owner_name, count in tsv_owner_counts.most_common():
            print(f"    {owner_name}: {count}")

    # ---- Analysis 4: Accounts in delta but NOT in Agave ----
    print("\n" + "=" * 80)
    print("ANALYSIS 4: Delta accounts NOT in Agave TSV")
    print("=" * 80)

    missing_from_agave = []
    for pubkey, drec in sorted(delta.items()):
        if pubkey not in agave:
            missing_from_agave.append({
                'pubkey': pubkey,
                'owner': drec['owner'],
                'owner_name': KNOWN_PROGRAMS.get(drec['owner'], drec['owner'][:16] + "..."),
                'lamports': drec['curr_lamports'],
                'data_len': drec['curr_data_len'],
            })

    print(f"\n  Count: {len(missing_from_agave)}")
    if missing_from_agave:
        owner_counts = Counter(m['owner_name'] for m in missing_from_agave)
        print(f"\n  By owner:")
        for owner_name, count in owner_counts.most_common():
            print(f"    {owner_name}: {count}")
        print(f"\n  First 20:")
        for m in missing_from_agave[:20]:
            print(f"    {m['pubkey']} lamports={m['lamports']} len={m['data_len']} owner={m['owner_name']}")

    # ---- Analysis 5: Execution failures ----
    print("\n" + "=" * 80)
    print("ANALYSIS 5: Execution Failures in Slot 400699657")
    print("=" * 80)

    failures = parse_execution_failures(400699657)
    print(f"\n  Total execution failures: {len(failures)}")

    if failures:
        prog_counts = Counter(f['program'] for f in failures)
        err_counts = Counter(f['err'] for f in failures)
        print(f"\n  By program:")
        for prog, count in prog_counts.most_common():
            prog_name = KNOWN_PROGRAMS.get(prog, prog)
            print(f"    {prog_name}: {count}")
        print(f"\n  By error:")
        for err, count in err_counts.most_common():
            print(f"    {err}: {count}")

    # ---- Analysis 6: Lamport violations ----
    print("\n" + "=" * 80)
    print("ANALYSIS 6: Lamport Violations in Slot 400699657")
    print("=" * 80)

    violations = parse_lamport_violations(400699657)
    print(f"\n  Total lamport violations: {len(violations)}")

    if violations:
        # Group by unique payer/sig
        unique_sigs = set(v['sig'] for v in violations)
        print(f"  Unique transaction signatures: {len(unique_sigs)}")

        # Show some details
        print(f"\n  First 10 violations:")
        for i, v in enumerate(violations[:10]):
            print(f"  [{i+1}] sig={v['sig'][:32]}... delta={v['delta']} fee={v['fee']} accounts={v['num_accounts']}")
            for a in v['changed_accounts'][:3]:
                print(f"       acct[{a['index']}] {a['pubkey']} diff={a['diff']}")

        # Collect all account pubkeys involved in violations
        viol_accounts = set()
        for v in violations:
            for a in v['changed_accounts']:
                viol_accounts.add(a['pubkey'])
        print(f"\n  Unique accounts with lamport changes: {len(viol_accounts)}")

        # Check if any of these accounts have data hash mismatches
        viol_with_data_mismatch = [m for m in mismatches if m['pubkey'] in viol_accounts]
        print(f"  Of those, accounts with data hash mismatch: {len(viol_with_data_mismatch)}")

    # ---- Analysis 7: Vote accounts deep dive ----
    print("\n" + "=" * 80)
    print("ANALYSIS 7: Vote Account Data Hash Comparison (Binary)")
    print("=" * 80)

    vote_mismatches = [m for m in mismatches if m['owner_name'] == 'Vote Program']
    print(f"\n  Vote account data hash mismatches: {len(vote_mismatches)}")

    if vote_mismatches:
        # For the first few, show byte-level diff
        for vm in vote_mismatches[:3]:
            pubkey = vm['pubkey']
            agave_hash, agave_data, agave_size = load_agave_binary_hash(pubkey)
            print(f"\n  Vote account: {pubkey}")
            print(f"    SolanaC data_len={vm['sc_data_len']} hash={vm['sc_data_hash']}")
            print(f"    Agave   data_len={vm['agave_data_len']} hash={vm['agave_data_hash']}")
            if agave_data:
                # Parse vote account header (first ~53 bytes for V3)
                # Version discriminant (4 bytes) + ...
                if len(agave_data) >= 4:
                    version = int.from_bytes(agave_data[:4], 'little')
                    print(f"    Agave vote version discriminant: {version}")
                if len(agave_data) >= 36:
                    node_pk = agave_data[4:36]
                    print(f"    Agave node_pubkey: first 8 bytes = {node_pk[:8].hex()}")

    # ---- Analysis 8: Check sysvar_data_mismatch warnings ----
    print("\n" + "=" * 80)
    print("ANALYSIS 8: Sysvar Data Mismatches in Slot 400699657")
    print("=" * 80)

    sysvar_mismatches = []
    with open(LOG_FILE, 'r') as f:
        in_range = False
        for line in f:
            if "slot=400699657" in line:
                in_range = True
            if in_range and "sysvar_data_mismatch" in line:
                sysvar_mismatches.append(line.strip())
            if in_range and "slot=400699658" in line:
                break

    print(f"\n  Sysvar mismatch warnings: {len(sysvar_mismatches)}")
    for s in sysvar_mismatches[:10]:
        print(f"    {s}")

    # ---- Summary ----
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"""
  Delta accounts in slot 400699657: {len(delta)}
  Accounts also in Agave TSV:       {len(delta) - tsv_missing}
  Agave binary dumps available:     {bin_count}

  Data hash mismatches (binary):    {data_hash_mismatch}
  Data hash mismatches (TSV):       {tsv_hash_mismatch}
  Execution failures:               {len(failures)}
  Lamport violations:               {len(violations)}

  NOTE: The Agave TSV is from slot 400699659 (2 slots later),
  so vote accounts will have accumulated 2 more slots of votes.
  The binary dumps should be from the same later slot.
  Vote data hash differences are EXPECTED.

  FOCUS: Look for non-vote data hash mismatches as real bugs.
""")

    # Non-vote mismatches
    non_vote_mismatches = [m for m in mismatches if m['owner_name'] != 'Vote Program']
    print(f"  NON-VOTE data hash mismatches: {len(non_vote_mismatches)}")
    if non_vote_mismatches:
        nv_owner_counts = Counter(m['owner_name'] for m in non_vote_mismatches)
        print(f"\n  By owner:")
        for owner_name, count in nv_owner_counts.most_common():
            print(f"    {owner_name}: {count}")
        print(f"\n  Details:")
        for m in non_vote_mismatches[:30]:
            print(f"    {m['pubkey']} owner={m['owner_name']} sc_len={m['sc_data_len']} agave_len={m['agave_data_len']} sc_hash={m['sc_data_hash']} agave_hash={m['agave_data_hash']}")

if __name__ == '__main__':
    main()
