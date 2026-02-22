#!/usr/bin/env python3
"""
Compare Agave's post-execution account data with solana-c's binary dumps.
Requires Agave RPC to be running at slot >= 400585392.
"""
import json
import subprocess
import sys
import base64
import hashlib
import csv
import os
import struct

try:
    import blake3
except ImportError:
    print("ERROR: blake3 required")
    sys.exit(1)

DUMP_DIR = "/home/ubuntu/solana-c/delta_dumps_parity23"
SLOT = 400585392
RPC_URL = "http://127.0.0.1:18999"
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
    if lamports == 0:
        return bytes(LT_HASH_BYTES)
    h = blake3.blake3()
    h.update(struct.pack('<Q', lamports))
    h.update(data)
    h.update(struct.pack('B', 1 if executable else 0))
    h.update(owner_bytes)
    h.update(pubkey_bytes)
    return h.digest(length=LT_HASH_BYTES)

def query_account(pubkey):
    try:
        r = subprocess.run(['curl', '-s', '--max-time', '5', '-X', 'POST', RPC_URL,
            '-H', 'Content-Type: application/json',
            '-d', json.dumps({'jsonrpc':'2.0','id':1,'method':'getAccountInfo',
                'params':[pubkey,{'encoding':'base64','commitment':'processed'}]})],
            capture_output=True, text=True, timeout=10)
        d = json.loads(r.stdout)
        return d['result']['value']
    except Exception as e:
        return f"ERROR: {e}"

def main():
    # First check if Agave is at the right slot
    try:
        r = subprocess.run(['curl', '-s', '--max-time', '3', '-X', 'POST', RPC_URL,
            '-H', 'Content-Type: application/json',
            '-d', '{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[{"commitment":"processed"}]}'],
            capture_output=True, text=True, timeout=5)
        d = json.loads(r.stdout)
        agave_slot = d['result']
        print(f"Agave is at slot: {agave_slot}")
        if agave_slot < SLOT:
            print(f"ERROR: Agave hasn't replayed slot {SLOT} yet (at {agave_slot})")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR querying Agave slot: {e}")
        sys.exit(1)

    tsv_path = os.path.join(DUMP_DIR, f"delta_accounts.{SLOT}.tsv")
    rows = []
    with open(tsv_path) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            rows.append(row)

    print(f"Total accounts in delta: {len(rows)}")

    mismatches_lamports = []
    mismatches_data = []
    mismatches_owner = []
    mismatches_executable = []
    matches = 0
    errors = 0

    # Track lt_hash difference
    lt_hash_diff = [0] * NUM_ELEMENTS

    for i, row in enumerate(rows):
        if i % 200 == 0 and i > 0:
            print(f"  Progress: {i}/{len(rows)} (matches={matches}, data_mismatch={len(mismatches_data)}, errors={errors})")

        pubkey = row['pubkey']
        curr_lamports = int(row['curr_lamports'])
        curr_data_len = int(row['curr_data_len'])
        executable = int(row['executable'])
        owner = row['owner']

        agave_val = query_account(pubkey)
        if isinstance(agave_val, str) and agave_val.startswith("ERROR"):
            errors += 1
            continue

        # Get Agave account data
        if agave_val is None:
            agave_lamports = 0
            agave_data = b''
            agave_executable = False
            agave_owner = "11111111111111111111111111111111"
        else:
            agave_lamports = agave_val['lamports']
            agave_data = base64.b64decode(agave_val['data'][0])
            agave_executable = agave_val['executable']
            agave_owner = agave_val['owner']

        # Compare lamports
        if agave_lamports != curr_lamports:
            mismatches_lamports.append({
                'pubkey': pubkey, 'agave': agave_lamports, 'solanac': curr_lamports,
                'owner': owner, 'diff': agave_lamports - curr_lamports
            })
            continue

        # Compare owner
        if agave_owner != owner:
            mismatches_owner.append({'pubkey': pubkey, 'agave': agave_owner, 'solanac': owner})
            continue

        # Compare executable
        if (1 if agave_executable else 0) != executable:
            mismatches_executable.append({'pubkey': pubkey, 'agave': agave_executable, 'solanac': executable})
            continue

        # Compare data
        if curr_data_len > 0:
            # Load solana-c's binary dump
            solanac_data = None
            for prefix in ['solanac_sysvar', 'solanac_vote', 'solanac_acct']:
                candidate = os.path.join(DUMP_DIR, f"{prefix}_{SLOT}_{pubkey}.bin")
                if os.path.exists(candidate):
                    with open(candidate, 'rb') as f:
                        solanac_data = f.read()
                    break

            if solanac_data is None:
                errors += 1
                continue

            if len(agave_data) != len(solanac_data):
                mismatches_data.append({
                    'pubkey': pubkey, 'field': 'data_len',
                    'agave': len(agave_data), 'solanac': len(solanac_data),
                    'owner': owner
                })
                continue

            if agave_data != solanac_data:
                # Find first differing byte
                first_diff = -1
                for j in range(len(agave_data)):
                    if agave_data[j] != solanac_data[j]:
                        first_diff = j
                        break

                mismatches_data.append({
                    'pubkey': pubkey, 'field': 'data_content',
                    'data_len': len(agave_data), 'first_diff_byte': first_diff,
                    'agave_byte': agave_data[first_diff] if first_diff >= 0 else None,
                    'solanac_byte': solanac_data[first_diff] if first_diff >= 0 else None,
                    'owner': owner,
                    'agave_hash': hashlib.sha256(agave_data).hexdigest()[:16],
                    'solanac_hash': hashlib.sha256(solanac_data).hexdigest()[:16]
                })

                # Compute lt_hash difference for this account
                pubkey_bytes = (b58decode(pubkey) + b'\x00' * 32)[:32]
                owner_bytes = (b58decode(owner) + b'\x00' * 32)[:32]

                agave_lt = compute_account_lt_hash(pubkey_bytes, agave_lamports, agave_data, agave_executable, owner_bytes)
                solanac_lt = compute_account_lt_hash(pubkey_bytes, curr_lamports, solanac_data, executable, owner_bytes)

                agave_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', agave_lt)
                solanac_u16 = struct.unpack(f'<{NUM_ELEMENTS}H', solanac_lt)

                for k in range(NUM_ELEMENTS):
                    lt_hash_diff[k] = (lt_hash_diff[k] + agave_u16[k] - solanac_u16[k]) & 0xFFFF

                continue
        elif agave_val is not None and len(agave_data) != curr_data_len:
            mismatches_data.append({
                'pubkey': pubkey, 'field': 'data_len',
                'agave': len(agave_data), 'solanac': curr_data_len,
                'owner': owner
            })
            continue

        matches += 1

    print(f"\n=== Results ===")
    print(f"Matches: {matches}")
    print(f"Lamport mismatches: {len(mismatches_lamports)}")
    print(f"Data mismatches: {len(mismatches_data)}")
    print(f"Owner mismatches: {len(mismatches_owner)}")
    print(f"Executable mismatches: {len(mismatches_executable)}")
    print(f"Errors: {errors}")

    if mismatches_lamports:
        print(f"\n=== Lamport Mismatches (first 10) ===")
        for m in mismatches_lamports[:10]:
            print(f"  {m['pubkey'][:20]}... agave={m['agave']} solanac={m['solanac']} diff={m['diff']} owner={m['owner'][:16]}...")

    if mismatches_data:
        print(f"\n=== Data Mismatches (first 20) ===")
        from collections import Counter
        by_owner = Counter(m['owner'] for m in mismatches_data)
        print(f"By owner: {dict(by_owner)}")
        for m in mismatches_data[:20]:
            print(f"  {m['pubkey'][:20]}... field={m['field']} owner={m['owner'][:16]}...", end='')
            if 'first_diff_byte' in m:
                print(f" first_diff@{m['first_diff_byte']} agave=0x{m.get('agave_byte',0):02x} solanac=0x{m.get('solanac_byte',0):02x}", end='')
            if 'agave_hash' in m:
                print(f" agave_hash={m['agave_hash']} solanac_hash={m['solanac_hash']}", end='')
            print()

    # Check if lt_hash_diff is all zeros (meaning data mismatches cancel out or don't contribute)
    lt_hash_diff_nonzero = sum(1 for x in lt_hash_diff if x != 0)
    if lt_hash_diff_nonzero > 0:
        print(f"\n=== Lt_hash difference from data mismatches ===")
        print(f"Non-zero elements: {lt_hash_diff_nonzero}/{NUM_ELEMENTS}")
    else:
        print(f"\nAll data mismatches contribute zero to lt_hash (possibly rent_epoch-only)")

if __name__ == '__main__':
    main()
