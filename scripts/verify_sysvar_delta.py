#!/usr/bin/env python3
"""
Independently compute the sysvar-only lt_hash delta from binary dumps
and compare against solana-c's sysvar_delta binary.
"""
import os
import sys
import struct
import hashlib

try:
    import blake3
except ImportError:
    print("ERROR: blake3 module required. pip install blake3")
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

# Sysvar accounts and their metadata from the TSV
SYSVARS = {
    'SysvarC1ock11111111111111111111111111111111': {
        'lamports': 1169280,
        'owner': 'Sysvar1111111111111111111111111111111111111',
        'executable': 0,
    },
    'SysvarRecentB1ockHashes11111111111111111111': {
        'lamports': 42706560,
        'owner': 'Sysvar1111111111111111111111111111111111111',
        'executable': 0,
    },
    'SysvarS1otHashes111111111111111111111111111': {
        'lamports': 143487360,
        'owner': 'Sysvar1111111111111111111111111111111111111',
        'executable': 0,
    },
    'SysvarS1otHistory11111111111111111111111111': {
        'lamports': 913326000,
        'owner': 'Sysvar1111111111111111111111111111111111111',
        'executable': 0,
    },
}

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

def main():
    delta = [0] * NUM_ELEMENTS

    for sysvar_b58, meta in SYSVARS.items():
        pubkey_bytes = b58decode(sysvar_b58)
        pubkey_bytes = (pubkey_bytes + b'\x00' * 32)[:32]
        owner_bytes = b58decode(meta['owner'])
        owner_bytes = (owner_bytes + b'\x00' * 32)[:32]
        lamports = meta['lamports']
        executable = meta['executable']

        # Load curr binary
        curr_path = os.path.join(DUMP_DIR, f"solanac_sysvar_{SLOT}_{sysvar_b58}.bin")
        with open(curr_path, 'rb') as f:
            curr_data = f.read()

        # Load prev binary
        prev_path = os.path.join(DUMP_DIR, f"solanac_sysvar_prev_{SLOT}_{sysvar_b58}.bin")
        with open(prev_path, 'rb') as f:
            prev_data = f.read()

        print(f"Sysvar: {sysvar_b58[:20]}...")
        print(f"  lamports={lamports} executable={executable}")
        print(f"  curr_data_len={len(curr_data)} prev_data_len={len(prev_data)}")
        print(f"  curr_sha256={hashlib.sha256(curr_data).hexdigest()[:16]}")
        print(f"  prev_sha256={hashlib.sha256(prev_data).hexdigest()[:16]}")

        # Check if data actually changed
        if curr_data == prev_data:
            print(f"  DATA UNCHANGED — zero contribution")
            continue

        # Compute lt_hashes
        curr_lt = compute_account_lt_hash(pubkey_bytes, lamports, curr_data, executable, owner_bytes)
        prev_lt = compute_account_lt_hash(pubkey_bytes, lamports, prev_data, executable, owner_bytes)

        curr_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', curr_lt)
        prev_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', prev_lt)

        for i in range(NUM_ELEMENTS):
            delta[i] = (delta[i] - prev_u16[i] + curr_u16[i]) & 0xFFFF

        print(f"  Data changed — contributing to delta")

    # Convert to bytes
    delta_bytes = struct.pack(f'<{NUM_ELEMENTS}H', *delta)
    delta_sha = hashlib.sha256(delta_bytes).hexdigest()
    print(f"\nPython sysvar delta SHA256: {delta_sha}")

    # Load C sysvar delta
    c_sysvar_path = os.path.join(DUMP_DIR, f"lt_hash_sysvar_delta.{SLOT}.bin")
    with open(c_sysvar_path, 'rb') as f:
        c_sysvar_delta = f.read()
    c_sysvar_sha = hashlib.sha256(c_sysvar_delta).hexdigest()
    print(f"C code sysvar delta SHA256: {c_sysvar_sha}")

    if delta_bytes == c_sysvar_delta:
        print("\nSysvar delta MATCH!")
    else:
        print("\nSysvar delta MISMATCH!")
        mismatches = 0
        for i in range(NUM_ELEMENTS):
            py_val = struct.unpack_from('<H', delta_bytes, i*2)[0]
            c_val = struct.unpack_from('<H', c_sysvar_delta, i*2)[0]
            if py_val != c_val:
                if mismatches < 5:
                    print(f"  Element {i}: Python={py_val} C={c_val}")
                mismatches += 1
        print(f"  Total mismatched elements: {mismatches}/{NUM_ELEMENTS}")

    # Also verify nonsysvar delta
    print("\n--- Non-sysvar delta verification ---")
    c_nonsysvar_path = os.path.join(DUMP_DIR, f"lt_hash_nonsysvar_delta.{SLOT}.bin")
    c_base_path = os.path.join(DUMP_DIR, f"lt_hash_base.{SLOT}.bin")
    c_final_path = os.path.join(DUMP_DIR, f"lt_hash_final.{SLOT}.bin")

    with open(c_nonsysvar_path, 'rb') as f:
        c_nonsysvar = f.read()
    with open(c_base_path, 'rb') as f:
        c_base = f.read()
    with open(c_final_path, 'rb') as f:
        c_final = f.read()

    # Verify: base + sysvar_delta + nonsysvar_delta == final
    base_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', c_base)
    sysvar_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', c_sysvar_delta)
    nonsysvar_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', c_nonsysvar)
    final_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', c_final)

    reconstructed = [(base_u16[i] + sysvar_u16[i] + nonsysvar_u16[i]) & 0xFFFF for i in range(NUM_ELEMENTS)]
    reconstructed_bytes = struct.pack(f'<{NUM_ELEMENTS}H', *reconstructed)
    if reconstructed_bytes == c_final:
        print("base + sysvar_delta + nonsysvar_delta == final: VERIFIED")
    else:
        print("base + sysvar_delta + nonsysvar_delta != final: BUG!")

    print(f"\nNon-sysvar delta SHA256: {hashlib.sha256(c_nonsysvar).hexdigest()}")

if __name__ == '__main__':
    main()
