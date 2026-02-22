#!/usr/bin/env python3
"""
Verify vote account lt_hash values from binary dumps vs delta TSV.
Uses blake3 XOF to independently compute lt_hash for each account.
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
    print("ERROR: blake3 module not found. Install with: pip install blake3")
    sys.exit(1)

DUMP_DIR = sys.argv[1] if len(sys.argv) > 1 else "/home/ubuntu/solana-c/delta_dumps_parity22"
SLOT = 400585392
LT_HASH_BYTES = 2048  # 1024 uint16 elements = 2048 bytes

# Base58 alphabet
B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58decode(s):
    """Decode base58 string to bytes."""
    n = 0
    for c in s.encode():
        n = n * 58 + B58_ALPHABET.index(c)
    result = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    # Add leading zeros
    pad = 0
    for c in s.encode():
        if c == B58_ALPHABET[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + result

def compute_account_lt_hash(pubkey_bytes, lamports, data, executable, owner_bytes):
    """Compute the BLAKE3-XOF lt_hash for an account."""
    if lamports == 0:
        return bytes(LT_HASH_BYTES)  # Identity for dead accounts

    h = blake3.blake3()
    h.update(struct.pack('<Q', lamports))
    h.update(data)
    h.update(struct.pack('B', 1 if executable else 0))
    h.update(owner_bytes)
    h.update(pubkey_bytes)
    return h.digest(length=LT_HASH_BYTES)

def main():
    # Load delta TSV
    tsv_path = os.path.join(DUMP_DIR, f"delta_accounts.{SLOT}.tsv")
    tsv_data = {}
    with open(tsv_path) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            tsv_data[row['pubkey']] = row

    # Find vote account dumps
    pattern = os.path.join(DUMP_DIR, f"solanac_vote_{SLOT}_*.bin")
    curr_files = sorted(glob.glob(pattern))
    print(f"Found {len(curr_files)} vote account dumps")

    vote_owner = b58decode("Vote111111111111111111111111111111111111111")
    # Pad/truncate to 32 bytes
    vote_owner = (vote_owner + b'\x00' * 32)[:32]

    mismatches = 0
    verified = 0
    skipped = 0

    for curr_file in curr_files:
        basename = os.path.basename(curr_file)
        parts = basename.replace('.bin', '').split('_', 3)
        pubkey_b58 = parts[3] if len(parts) > 3 else 'unknown'

        # Get pubkey bytes
        try:
            pubkey_bytes = b58decode(pubkey_b58)
            pubkey_bytes = (pubkey_bytes + b'\x00' * 32)[:32]
        except Exception:
            skipped += 1
            continue

        # Read current data
        with open(curr_file, 'rb') as f:
            curr_data = f.read()

        # Get TSV row
        row = tsv_data.get(pubkey_b58)
        if not row:
            skipped += 1
            continue

        lamports = int(row['curr_lamports'])
        executable = int(row['executable'])

        # Compute lt_hash
        computed_hash = compute_account_lt_hash(pubkey_bytes, lamports, curr_data, executable, vote_owner)

        # Compare with TSV curr_lthash (first 16 bytes hex)
        computed_hex = computed_hash[:16].hex()
        tsv_hex = row['curr_lthash']

        if computed_hex == tsv_hex:
            verified += 1
        else:
            mismatches += 1
            if mismatches <= 10:
                print(f"MISMATCH {pubkey_b58}: computed={computed_hex} tsv={tsv_hex}")
                print(f"  lamports={lamports} data_len={len(curr_data)} exec={executable}")

        # Also verify prev if available
        prev_file = curr_file.replace(f'solanac_vote_{SLOT}_', f'solanac_vote_prev_{SLOT}_')
        if os.path.exists(prev_file):
            with open(prev_file, 'rb') as f:
                prev_data = f.read()
            prev_lamports = int(row['prev_lamports'])
            prev_hash = compute_account_lt_hash(pubkey_bytes, prev_lamports, prev_data, executable, vote_owner)
            prev_computed_hex = prev_hash[:16].hex()
            prev_tsv_hex = row['prev_lthash']
            if prev_computed_hex != prev_tsv_hex:
                if mismatches <= 10:
                    print(f"PREV MISMATCH {pubkey_b58}: computed={prev_computed_hex} tsv={prev_tsv_hex}")

    print(f"\nResults: verified={verified} mismatches={mismatches} skipped={skipped}")

    # Now compute the total vote delta contribution
    print("\n=== Computing vote delta contribution ===")
    vote_delta = [0] * 1024  # uint16 array

    for curr_file in curr_files:
        basename = os.path.basename(curr_file)
        parts = basename.replace('.bin', '').split('_', 3)
        pubkey_b58 = parts[3] if len(parts) > 3 else 'unknown'

        try:
            pubkey_bytes = b58decode(pubkey_b58)
            pubkey_bytes = (pubkey_bytes + b'\x00' * 32)[:32]
        except Exception:
            continue

        row = tsv_data.get(pubkey_b58)
        if not row:
            continue

        with open(curr_file, 'rb') as f:
            curr_data = f.read()

        curr_lamports = int(row['curr_lamports'])
        executable = int(row['executable'])

        # Curr hash
        curr_hash = compute_account_lt_hash(pubkey_bytes, curr_lamports, curr_data, executable, vote_owner)

        # Prev hash
        prev_file = curr_file.replace(f'solanac_vote_{SLOT}_', f'solanac_vote_prev_{SLOT}_')
        if os.path.exists(prev_file):
            with open(prev_file, 'rb') as f:
                prev_data = f.read()
            prev_lamports = int(row['prev_lamports'])
            prev_hash = compute_account_lt_hash(pubkey_bytes, prev_lamports, prev_data, executable, vote_owner)
        else:
            prev_hash = bytes(LT_HASH_BYTES)

        # Mix out prev, mix in curr
        curr_u16 = struct.unpack('<1024H', curr_hash)
        prev_u16 = struct.unpack('<1024H', prev_hash)

        for i in range(1024):
            vote_delta[i] = (vote_delta[i] - prev_u16[i] + curr_u16[i]) & 0xFFFF

    # Convert to bytes and print checksum
    vote_delta_bytes = struct.pack('<1024H', *vote_delta)
    delta_sha = hashlib.sha256(vote_delta_bytes).hexdigest()
    print(f"Vote-only delta SHA256: {delta_sha}")

    # Load the nonsysvar delta from the binary dump
    nonsysvar_delta_path = os.path.join(DUMP_DIR, f"lt_hash_nonsysvar_delta.{SLOT}.bin")
    if os.path.exists(nonsysvar_delta_path):
        with open(nonsysvar_delta_path, 'rb') as f:
            nonsysvar_delta = f.read()
        nonsysvar_sha = hashlib.sha256(nonsysvar_delta).hexdigest()
        print(f"Non-sysvar delta SHA256: {nonsysvar_sha}")

        # Compute non-vote-non-sysvar delta (subtract vote from nonsysvar)
        nonsysvar_u16 = struct.unpack('<1024H', nonsysvar_delta)
        nonvote_delta = [0] * 1024
        for i in range(1024):
            nonvote_delta[i] = (nonsysvar_u16[i] - vote_delta[i]) & 0xFFFF

        nonvote_bytes = struct.pack('<1024H', *nonvote_delta)
        nonvote_sha = hashlib.sha256(nonvote_bytes).hexdigest()
        print(f"Non-vote-non-sysvar delta SHA256: {nonvote_sha}")

        # Check if non-vote delta is identity (all zeros)
        is_identity = all(v == 0 for v in nonvote_delta)
        print(f"Non-vote-non-sysvar delta is identity (zero): {is_identity}")

if __name__ == '__main__':
    main()
