#!/usr/bin/env python3
"""
Independently compute the full lt_hash delta from account binary dumps + TSV,
then compare against the binary delta from solana-c.
This verifies that the C code's delta computation matches a Python reference.
"""
import os
import sys
import struct
import csv
import hashlib

try:
    import blake3
except ImportError:
    print("ERROR: blake3 module not found. Install with: pip install blake3")
    sys.exit(1)

DUMP_DIR = sys.argv[1] if len(sys.argv) > 1 else "/home/ubuntu/solana-c/delta_dumps_parity23"
SLOT = 400585392
LT_HASH_BYTES = 2048
NUM_ELEMENTS = 1024

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
    """Compute BLAKE3-XOF lt_hash for an account."""
    if lamports == 0:
        return bytes(LT_HASH_BYTES)
    h = blake3.blake3()
    h.update(struct.pack('<Q', lamports))
    h.update(data)
    h.update(struct.pack('B', 1 if executable else 0))
    h.update(owner_bytes)
    h.update(pubkey_bytes)
    return h.digest(length=LT_HASH_BYTES)

def load_account_lt_hash(pubkey_b58, lamports, data_len, executable, owner_b58, dump_dir, slot, prefix_list):
    """Load binary dump and compute lt_hash. Returns (lt_hash_bytes, source)."""
    pubkey_bytes = b58decode(pubkey_b58)
    pubkey_bytes = (pubkey_bytes + b'\x00' * 32)[:32]
    owner_bytes = b58decode(owner_b58)
    owner_bytes = (owner_bytes + b'\x00' * 32)[:32]

    if lamports == 0:
        return bytes(LT_HASH_BYTES), "zero_lamports"

    if data_len == 0:
        return compute_account_lt_hash(pubkey_bytes, lamports, b'', executable, owner_bytes), "zero_data"

    # Try to find binary dump
    for prefix in prefix_list:
        candidate = os.path.join(dump_dir, f"{prefix}_{slot}_{pubkey_b58}.bin")
        if os.path.exists(candidate):
            with open(candidate, 'rb') as f:
                data = f.read()
            return compute_account_lt_hash(pubkey_bytes, lamports, data, executable, owner_bytes), prefix

    return None, "no_dump"

def main():
    tsv_path = os.path.join(DUMP_DIR, f"delta_accounts.{SLOT}.tsv")

    # Compute the delta independently
    delta = [0] * NUM_ELEMENTS  # uint16 array
    n_processed = 0
    n_skipped = 0

    with open(tsv_path) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            pubkey = row['pubkey']
            owner = row['owner']
            curr_lamports = int(row['curr_lamports'])
            prev_lamports = int(row['prev_lamports'])
            curr_data_len = int(row['curr_data_len'])
            prev_data_len = int(row['prev_data_len'])
            executable = int(row['executable'])

            # Compute curr lt_hash
            curr_hash, curr_src = load_account_lt_hash(
                pubkey, curr_lamports, curr_data_len, executable, owner,
                DUMP_DIR, SLOT, ['solanac_sysvar', 'solanac_vote', 'solanac_acct'])

            if curr_hash is None:
                n_skipped += 1
                continue

            # Compute prev lt_hash
            prev_hash, prev_src = load_account_lt_hash(
                pubkey, prev_lamports, prev_data_len, executable, owner,
                DUMP_DIR, SLOT, ['solanac_sysvar_prev', 'solanac_vote_prev', 'solanac_acct_prev'])

            if prev_hash is None:
                n_skipped += 1
                continue

            # Mix out prev, mix in curr
            curr_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', curr_hash)
            prev_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', prev_hash)

            for i in range(NUM_ELEMENTS):
                delta[i] = (delta[i] - prev_u16[i] + curr_u16[i]) & 0xFFFF

            n_processed += 1

    print(f"Processed: {n_processed}, Skipped: {n_skipped}")

    # Convert delta to bytes
    delta_bytes = struct.pack(f'<{NUM_ELEMENTS}H', *delta)
    delta_sha = hashlib.sha256(delta_bytes).hexdigest()
    print(f"Python delta SHA256: {delta_sha}")

    # Load the binary files from solana-c
    base_path = os.path.join(DUMP_DIR, f"lt_hash_base.{SLOT}.bin")
    final_path = os.path.join(DUMP_DIR, f"lt_hash_final.{SLOT}.bin")

    with open(base_path, 'rb') as f:
        base = f.read()
    with open(final_path, 'rb') as f:
        final_lt = f.read()

    # Compute C delta (final - base)
    base_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', base)
    final_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', final_lt)
    c_delta = [(final_u16[i] - base_u16[i]) & 0xFFFF for i in range(NUM_ELEMENTS)]
    c_delta_bytes = struct.pack(f'<{NUM_ELEMENTS}H', *c_delta)
    c_delta_sha = hashlib.sha256(c_delta_bytes).hexdigest()
    print(f"C code delta SHA256: {c_delta_sha}")

    # Compare
    if delta_bytes == c_delta_bytes:
        print("\nDelta MATCH: Python independently computes the same delta as C code.")
    else:
        print("\nDelta MISMATCH!")
        # Find where they differ
        for i in range(NUM_ELEMENTS):
            py_val = struct.unpack_from('<H', delta_bytes, i*2)[0]
            c_val = struct.unpack_from('<H', c_delta_bytes, i*2)[0]
            if py_val != c_val:
                print(f"  Element {i}: Python={py_val} C={c_val}")
                if i > 5:
                    print(f"  ... (showing first 6 mismatches)")
                    break

    # Also verify: base + python_delta should equal C final
    reconstructed = [(base_u16[i] + delta[i]) & 0xFFFF for i in range(NUM_ELEMENTS)]
    reconstructed_bytes = struct.pack(f'<{NUM_ELEMENTS}H', *reconstructed)
    if reconstructed_bytes == final_lt:
        print("Reconstruction: base + python_delta == C final. VERIFIED.")
    else:
        print("Reconstruction: base + python_delta != C final. BUG!")

if __name__ == '__main__':
    main()
