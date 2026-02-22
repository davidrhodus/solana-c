#!/usr/bin/env python3
"""
Byte-level comparison of specific mismatched accounts.
Focus on non-vote accounts that were only modified in slot 657 but have different data hashes.
"""

import os
import sys
import hashlib
import struct

BASE_DIR = "/home/ubuntu/solana-c/ledger.parity.1771302063"

# Non-vote true mismatches from Analysis 2 output
# These accounts were ONLY modified in slot 657 (not 658/659) and have hash differences
INTERESTING_ACCOUNTS = [
    # Token Program accounts (165 bytes each)
    ("2n6fxuD6PA5NYgEnXXYMh2iWD1JBJ1LGf76kFJAayZmX", "Token Program", 165),
    ("2dvBP5gB9Bv5zNQ8iyPN1oidVPvH61e5RPPC16VUZFzz", "Token-2022", 170),
    # dijkstra accounts (32 bytes)
    ("12jcZpK8ggSk2ppnKsbqno6zqbqTMS2rq2jAxNj3moKs", "dijkstra", 32),
    ("vCDwWKdqPHYAP7q5zXY6xk3XC5Ct5oqCs5fdpoosPNq", "dijkstra", 32),
    # System Program accounts with data
    ("3KsGpmXy4oMVHUjFrEJxwzVtfDFEKMfNucfKtYtNquf4", "System", 80),
    # 9H6tua (Openbook?) accounts
    ("hKgG7iEDRFNsJSwLYqz8ETHuZwzh6qMMLow8VXa8pLm", "9H6tua", 1728),
]

def load_delta_account(pubkey):
    """Load a specific account from delta TSV."""
    with open(os.path.join(BASE_DIR, "delta_accounts.400699657.tsv"), 'r') as f:
        header = f.readline().strip().split('\t')
        for line in f:
            fields = line.strip().split('\t')
            if len(fields) < len(header):
                continue
            rec = dict(zip(header, fields))
            if rec['pubkey'] == pubkey:
                return rec
    return None

def load_agave_binary(pubkey):
    """Load agave binary dump."""
    path = os.path.join(BASE_DIR, f"agave_acct_{pubkey}.bin")
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as f:
        return f.read()

def hexdump(data, start=0, length=None):
    """Pretty hex dump."""
    if length:
        data = data[start:start+length]
    else:
        data = data[start:]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"    {start+i:04x}: {hex_str:<48s} {ascii_str}")
    return '\n'.join(lines)

def parse_token_account(data):
    """Parse SPL Token account (165 bytes)."""
    if len(data) < 165:
        return None
    mint = data[0:32]
    owner = data[32:64]
    amount = struct.unpack('<Q', data[64:72])[0]
    delegate_opt = struct.unpack('<I', data[72:76])[0]
    delegate = data[76:108] if delegate_opt else None
    state = data[108]
    is_native_opt = struct.unpack('<I', data[109:113])[0]
    is_native = struct.unpack('<Q', data[113:121])[0] if is_native_opt else None
    delegated_amount = struct.unpack('<Q', data[121:129])[0]
    close_authority_opt = struct.unpack('<I', data[129:133])[0]
    close_authority = data[133:165] if close_authority_opt else None
    return {
        'mint': mint.hex(),
        'owner': owner.hex(),
        'amount': amount,
        'delegate_opt': delegate_opt,
        'state': state,
        'is_native_opt': is_native_opt,
        'delegated_amount': delegated_amount,
        'close_authority_opt': close_authority_opt,
    }

def main():
    print("=" * 80)
    print("BYTE-LEVEL COMPARISON OF NON-VOTE MISMATCHED ACCOUNTS")
    print("=" * 80)

    for pubkey, label, expected_len in INTERESTING_ACCOUNTS:
        print(f"\n{'=' * 80}")
        print(f"Account: {pubkey} ({label}, {expected_len} bytes)")
        print(f"{'=' * 80}")

        drec = load_delta_account(pubkey)
        agave_data = load_agave_binary(pubkey)

        if not drec:
            print("  NOT FOUND in delta")
            continue
        if agave_data is None:
            print("  NO agave binary dump")
            continue

        print(f"  SolanaC: lamports={drec['curr_lamports']} data_len={drec['curr_data_len']} hash={drec['data_hash']}")
        agave_hash = hashlib.sha256(agave_data).hexdigest()[:16]
        print(f"  Agave:   data_len={len(agave_data)} hash={agave_hash}")

        # We don't have SolanaC's raw data, only the hash.
        # But we DO have the Agave data. Let's dump it.
        print(f"\n  Agave binary data ({len(agave_data)} bytes):")
        print(hexdump(agave_data[:min(256, len(agave_data))]))
        if len(agave_data) > 256:
            print(f"    ... ({len(agave_data) - 256} more bytes)")

        if label == "Token Program" and len(agave_data) == 165:
            parsed = parse_token_account(agave_data)
            if parsed:
                print(f"\n  Parsed Token account:")
                for k, v in parsed.items():
                    print(f"    {k}: {v}")

    # Now let's look at execution_failed transactions more carefully
    # The original script found 0 - let me recheck
    print("\n" + "=" * 80)
    print("RECHECKING EXECUTION FAILURES FOR SLOT 400699657")
    print("=" * 80)

    import re
    exec_fail_pattern = re.compile(r'execution_failed: slot=400699657')
    count = 0
    with open(os.path.join(BASE_DIR, "solanac.validator.log"), 'r') as f:
        for line in f:
            if exec_fail_pattern.search(line):
                count += 1
                if count <= 5:
                    print(f"  {line.strip()}")
    print(f"\n  Total execution_failed for slot 400699657: {count}")

    # Check for all error types in this slot
    print("\n" + "=" * 80)
    print("ALL tx_result ERRORS IN SLOT 400699657")
    print("=" * 80)

    tx_pattern = re.compile(r'tx_result: slot=400699657 err=(-?\d+)')
    err_counts = {}
    with open(os.path.join(BASE_DIR, "solanac.validator.log"), 'r') as f:
        for line in f:
            m = tx_pattern.search(line)
            if m:
                err = int(m.group(1))
                err_counts[err] = err_counts.get(err, 0) + 1
    for err, cnt in sorted(err_counts.items()):
        print(f"  err={err}: {cnt} transactions")

    # Check for bank hash details
    print("\n" + "=" * 80)
    print("BANK HASH / LT_HASH DIAGNOSTIC FOR SLOT 400699657")
    print("=" * 80)

    with open(os.path.join(BASE_DIR, "solanac.validator.log"), 'r') as f:
        for line in f:
            if "400699657" in line and ("bank_hash" in line.lower() or "lt_hash" in line.lower() or "accounts_hash" in line.lower() or "MISMATCH" in line or "mismatch" in line):
                print(f"  {line.strip()}")

    # Check: the log mentioned sysvar_data_mismatch for Clock
    # Let's look at what the Clock sysvar values were
    print("\n" + "=" * 80)
    print("CLOCK SYSVAR MISMATCH DETAIL")
    print("=" * 80)

    with open(os.path.join(BASE_DIR, "solanac.validator.log"), 'r') as f:
        for line in f:
            if "sysvar_data_mismatch" in line and "400699657" in line.strip()[:80]:
                # Print the mismatch and the next few lines
                pass
            if "CLOCK_DIAG" in line and "400699657" in line:
                print(f"  {line.strip()}")
            if "sysvar_data_mismatch" in line and "C1ock" in line:
                print(f"  {line.strip()}")

    # Decode the existing/proposed clock bytes from the log
    existing = bytes.fromhex("0831e2170000000000ddf391690000000000009f03000000000000a003000000000000d85b936900000000")
    proposed = bytes.fromhex("0931e2170000000009ddf3916900000000009f03000000000000a003000000000000d95b936900000000")

    # Decode (wrong - let me parse better)
    existing = bytes.fromhex("0831e21700000000ddf3916900000000009f03000000000000a003000000000000d85b936900000000")
    proposed = bytes.fromhex("0931e21700000000ddf3916900000000009f03000000000000a003000000000000d95b936900000000")

    print(f"\n  Clock sysvar (40 bytes = slot:u64 + epoch_start_timestamp:i64 + epoch:u64 + leader_schedule_epoch:u64 + unix_timestamp:i64)")
    slot_e = struct.unpack('<Q', existing[0:8])[0]
    slot_p = struct.unpack('<Q', proposed[0:8])[0]
    epoch_start_ts_e = struct.unpack('<q', existing[8:16])[0]
    epoch_start_ts_p = struct.unpack('<q', proposed[8:16])[0]
    epoch_e = struct.unpack('<Q', existing[16:24])[0]
    epoch_p = struct.unpack('<Q', proposed[16:24])[0]
    leader_sched_e = struct.unpack('<Q', existing[24:32])[0]
    leader_sched_p = struct.unpack('<Q', proposed[24:32])[0]
    unix_ts_e = struct.unpack('<q', existing[32:40])[0]
    unix_ts_p = struct.unpack('<q', proposed[32:40])[0]

    print(f"  Existing: slot={slot_e} epoch_start_ts={epoch_start_ts_e} epoch={epoch_e} leader_sched={leader_sched_e} unix_ts={unix_ts_e}")
    print(f"  Proposed: slot={slot_p} epoch_start_ts={epoch_start_ts_p} epoch={epoch_p} leader_sched={leader_sched_p} unix_ts={unix_ts_p}")
    print(f"  Diff: slot={slot_p-slot_e} unix_ts={unix_ts_p-unix_ts_e}")

    # Check if vote accounts that matched vs mismatched have any pattern
    # (e.g., voted in this slot vs not)
    print("\n" + "=" * 80)
    print("VOTE ACCOUNT: Do matching ones have a pattern?")
    print("=" * 80)

    # Load delta to find vote accounts
    delta = {}
    with open(os.path.join(BASE_DIR, "delta_accounts.400699657.tsv"), 'r') as f:
        header = f.readline().strip().split('\t')
        for line in f:
            fields = line.strip().split('\t')
            if len(fields) < len(header):
                continue
            rec = dict(zip(header, fields))
            delta[rec['pubkey']] = rec

    vote_accounts = {k: v for k, v in delta.items()
                     if v['owner'] == 'Vote111111111111111111111111111111111111111'}

    print(f"  Total vote accounts in delta: {len(vote_accounts)}")

    # Check prev_data_hash vs data_hash to see if they changed
    vote_changed = sum(1 for v in vote_accounts.values() if v['data_hash'] != v['prev_data_hash'])
    vote_unchanged = sum(1 for v in vote_accounts.values() if v['data_hash'] == v['prev_data_hash'])
    print(f"  Vote data changed in 657: {vote_changed}")
    print(f"  Vote data unchanged in 657: {vote_unchanged}")

    # For the CiTY vote account, let's look at the binary diff
    pk = "CiTYUYPAPHdcri5yEfsmqVcs54J6j8X1QaiFLgYqMVe"
    print(f"\n  Example vote account: {pk}")
    drec = delta.get(pk)
    agave_data = load_agave_binary(pk)
    if drec and agave_data:
        print(f"    sc_hash={drec['data_hash']} sc_prev_hash={drec['prev_data_hash']}")
        print(f"    agave_hash={hashlib.sha256(agave_data).hexdigest()[:16]}")
        # Parse vote account header
        if len(agave_data) >= 4:
            version = struct.unpack('<I', agave_data[:4])[0]
            print(f"    version={version}")
        # votes start at a variable offset depending on authorized_voters etc
        # For V3 vote: version(4) + node_pubkey(32) + authorized_withdrawer(32) + commission(1)
        # + authorized_voters Vec + ...
        # Let's just show the first 128 bytes
        print(f"    First 128 bytes:")
        print(hexdump(agave_data[:128]))

    # Check the 132 lamport violation transactions - are they all from the same programs?
    print("\n" + "=" * 80)
    print("LAMPORT VIOLATION TX PROGRAMS")
    print("=" * 80)

    import re
    viol_sigs = set()
    viol_pattern = re.compile(
        r'LAMPORT_VIOLATION: slot=400699657 delta=(-?\d+) fee=(\d+) payer=(\S+) sig=(\S+)'
    )
    with open(os.path.join(BASE_DIR, "solanac.validator.log"), 'r') as f:
        for line in f:
            m = viol_pattern.search(line)
            if m:
                viol_sigs.add(m.group(4))

    # Find the program instructions for these tx
    # Look for the execution lines just before tx_result
    tx_programs = {}
    with open(os.path.join(BASE_DIR, "solanac.validator.log"), 'r') as f:
        last_elf = None
        for line in f:
            if "sol_bpf_elf.c" in line and "SBPF version" in line:
                # Extract version info
                last_elf = line.strip()
            m = re.search(r'tx_result: slot=400699657 err=(\S+) cu=(\d+) fee=(\d+) payer=(\S+) sig=(\S+)', line)
            if m:
                sig = m.group(5)
                if sig in viol_sigs:
                    tx_programs[sig] = last_elf

    print(f"\n  Violations with program info: {len(tx_programs)}")
    # Show a few
    for sig, prog in list(tx_programs.items())[:10]:
        print(f"    {sig[:40]}... -> {prog[-60:] if prog else 'N/A'}")

if __name__ == '__main__':
    main()
