#!/usr/bin/env python3
"""
Verify lt_hash values for ALL accounts in delta TSV.
For accounts with binary dumps (vote, sysvar), uses actual data.
For accounts without dumps (system, token), verifies from TSV metadata only.
"""
import os
import sys
import struct
import glob
import csv
import hashlib

try:
    import blake3
except ImportError:
    print("ERROR: blake3 module not found.")
    sys.exit(1)

DUMP_DIR = sys.argv[1] if len(sys.argv) > 1 else "/home/ubuntu/solana-c/delta_dumps_parity22"
SLOT = 400585392
LT_HASH_BYTES = 2048

B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58decode(s):
    n = 0
    for c in s.encode():
        n = n * 58 + B58_ALPHABET.index(c)
    result = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    pad = 0
    for c in s.encode():
        if c == B58_ALPHABET[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + result

def compute_account_lt_hash(pubkey_bytes, lamports, data, executable, owner_bytes):
    if lamports == 0:
        return bytes(LT_HASH_BYTES)
    h = blake3.blake3()
    h.update(struct.pack('<Q', lamports))
    h.update(data)
    h.update(struct.pack('B', 1 if executable else 0))
    h.update(owner_bytes)
    h.update(pubkey_bytes)
    return h.digest(length=LT_HASH_BYTES)

def compute_lt_hash_for_zero_data_account(pubkey_b58, lamports, executable, owner_b58):
    """Compute lt_hash for an account with 0 bytes of data."""
    pubkey_bytes = b58decode(pubkey_b58)
    pubkey_bytes = (pubkey_bytes + b'\x00' * 32)[:32]
    owner_bytes = b58decode(owner_b58)
    owner_bytes = (owner_bytes + b'\x00' * 32)[:32]
    return compute_account_lt_hash(pubkey_bytes, lamports, b'', executable, owner_bytes)

def main():
    tsv_path = os.path.join(DUMP_DIR, f"delta_accounts.{SLOT}.tsv")

    from collections import defaultdict
    stats = defaultdict(int)
    mismatches_by_owner = defaultdict(list)

    total_delta = [0] * 1024
    vote_delta = [0] * 1024
    system_delta = [0] * 1024
    token_delta = [0] * 1024
    other_delta = [0] * 1024

    with open(tsv_path) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            pubkey = row['pubkey']
            owner = row['owner']
            typ = row['type']
            curr_lamports = int(row['curr_lamports'])
            prev_lamports = int(row['prev_lamports'])
            curr_data_len = int(row['curr_data_len'])
            prev_data_len = int(row['prev_data_len'])
            executable = int(row['executable'])
            tsv_curr_lthash_hex = row['curr_lthash']
            tsv_prev_lthash_hex = row['prev_lthash']

            stats['total'] += 1

            # Try to verify curr lt_hash for zero-data accounts
            if curr_data_len == 0 and curr_lamports > 0:
                computed = compute_lt_hash_for_zero_data_account(pubkey, curr_lamports, executable, owner)
                computed_hex = computed[:16].hex()
                if computed_hex != tsv_curr_lthash_hex:
                    stats['curr_mismatch'] += 1
                    mismatches_by_owner[owner].append(f'{pubkey}: curr computed={computed_hex} tsv={tsv_curr_lthash_hex}')
                else:
                    stats['curr_verified'] += 1
            elif curr_data_len == 0 and curr_lamports == 0:
                # Removed account - curr hash should be identity
                identity_hex = '00' * 16
                if tsv_curr_lthash_hex != identity_hex:
                    stats['curr_mismatch'] += 1
                    mismatches_by_owner[owner].append(f'{pubkey}: removed but curr_lthash not identity: {tsv_curr_lthash_hex}')
                else:
                    stats['curr_verified'] += 1
            else:
                # Has data - check if we have a binary dump
                dump_file = None
                for prefix in ['solanac_vote', 'solanac_sysvar', 'solanac_acct']:
                    candidate = os.path.join(DUMP_DIR, f"{prefix}_{SLOT}_{pubkey}.bin")
                    if os.path.exists(candidate):
                        dump_file = candidate
                        break

                if dump_file:
                    with open(dump_file, 'rb') as df:
                        data = df.read()
                    pk_bytes = b58decode(pubkey)
                    pk_bytes = (pk_bytes + b'\x00' * 32)[:32]
                    own_bytes = b58decode(owner)
                    own_bytes = (own_bytes + b'\x00' * 32)[:32]
                    computed = compute_account_lt_hash(pk_bytes, curr_lamports, data, executable, own_bytes)
                    computed_hex = computed[:16].hex()
                    if computed_hex == tsv_curr_lthash_hex:
                        stats['curr_verified'] += 1
                    else:
                        stats['curr_mismatch'] += 1
                        mismatches_by_owner[owner].append(f'{pubkey}: dump mismatch computed={computed_hex} tsv={tsv_curr_lthash_hex} file={os.path.basename(dump_file)}')
                else:
                    stats['curr_no_dump'] += 1

            # Similarly verify prev
            if prev_data_len == 0 and prev_lamports > 0:
                computed = compute_lt_hash_for_zero_data_account(pubkey, prev_lamports, executable, owner)
                computed_hex = computed[:16].hex()
                if computed_hex != tsv_prev_lthash_hex:
                    stats['prev_mismatch'] += 1
                else:
                    stats['prev_verified'] += 1
            elif prev_data_len == 0 and prev_lamports == 0:
                identity_hex = '00' * 16
                if tsv_prev_lthash_hex != identity_hex:
                    stats['prev_mismatch'] += 1
                else:
                    stats['prev_verified'] += 1
            else:
                prev_dump = None
                for prefix in ['solanac_vote_prev', 'solanac_sysvar_prev', 'solanac_acct_prev']:
                    candidate = os.path.join(DUMP_DIR, f"{prefix}_{SLOT}_{pubkey}.bin")
                    if os.path.exists(candidate):
                        prev_dump = candidate
                        break
                if prev_dump:
                    with open(prev_dump, 'rb') as df:
                        data = df.read()
                    pk_bytes = b58decode(pubkey)
                    pk_bytes = (pk_bytes + b'\x00' * 32)[:32]
                    own_bytes = b58decode(owner)
                    own_bytes = (own_bytes + b'\x00' * 32)[:32]
                    computed = compute_account_lt_hash(pk_bytes, prev_lamports, data, executable, own_bytes)
                    computed_hex = computed[:16].hex()
                    if computed_hex == tsv_prev_lthash_hex:
                        stats['prev_verified'] += 1
                    else:
                        stats['prev_mismatch'] += 1
                else:
                    stats['prev_no_dump'] += 1

    print("=== Verification Results ===")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v}")

    if mismatches_by_owner:
        print("\n=== Mismatches by Owner ===")
        for owner, items in sorted(mismatches_by_owner.items()):
            print(f"\n  {owner}: {len(items)} mismatches")
            for item in items[:5]:
                print(f"    {item}")
    else:
        print("\nNo mismatches found!")

    # Summary by category
    verified_pct = (stats.get('curr_verified', 0) / max(1, stats['total'])) * 100
    no_dump_pct = (stats.get('curr_no_dump', 0) / max(1, stats['total'])) * 100
    print(f"\nCurr verified: {stats.get('curr_verified', 0)}/{stats['total']} ({verified_pct:.1f}%)")
    print(f"Curr no dump (BPF accounts): {stats.get('curr_no_dump', 0)}/{stats['total']} ({no_dump_pct:.1f}%)")

if __name__ == '__main__':
    main()
