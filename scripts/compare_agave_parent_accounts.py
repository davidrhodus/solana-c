#!/usr/bin/env python3
"""
Compare accounts from Agave RPC (parent bank at slot 400585391) with
solana-c's "prev" binary dumps to check if the prev state matches.
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
    """Query Agave RPC for account info."""
    try:
        r = subprocess.run(['curl', '-s', '--max-time', '3', '-X', 'POST', RPC_URL,
            '-H', 'Content-Type: application/json',
            '-d', json.dumps({'jsonrpc':'2.0','id':1,'method':'getAccountInfo',
                'params':[pubkey,{'encoding':'base64','commitment':'processed'}]})],
            capture_output=True, text=True, timeout=5)
        d = json.loads(r.stdout)
        return d['result']['value']
    except Exception as e:
        return f"ERROR: {e}"

def main():
    tsv_path = os.path.join(DUMP_DIR, f"delta_accounts.{SLOT}.tsv")

    # Load TSV
    rows = []
    with open(tsv_path) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            rows.append(row)

    print(f"Total accounts in delta: {len(rows)}")

    # Query all accounts from Agave (parent bank) and compare with prev state
    mismatches = []
    matches = 0
    errors = 0

    for i, row in enumerate(rows):
        if i % 200 == 0 and i > 0:
            print(f"  Progress: {i}/{len(rows)} (matches={matches}, mismatches={len(mismatches)}, errors={errors})")

        pubkey = row['pubkey']
        prev_lamports = int(row['prev_lamports'])
        prev_data_len = int(row['prev_data_len'])

        agave_val = query_account(pubkey)

        if isinstance(agave_val, str) and agave_val.startswith("ERROR"):
            errors += 1
            continue

        # Compare lamports
        if agave_val is None:
            agave_lamports = 0
            agave_data_len = 0
            agave_data_hash = "0" * 16
            agave_owner = "11111111111111111111111111111111"
            agave_executable = False
            agave_rent_epoch = 0
        else:
            agave_lamports = agave_val['lamports']
            agave_data = base64.b64decode(agave_val['data'][0])
            agave_data_len = len(agave_data)
            agave_data_hash = hashlib.sha256(agave_data).hexdigest()[:16]
            agave_owner = agave_val['owner']
            agave_executable = agave_val['executable']
            agave_rent_epoch = agave_val.get('rentEpoch', 0)

        # Compare with prev from TSV
        if agave_lamports != prev_lamports:
            mismatches.append({
                'pubkey': pubkey,
                'field': 'lamports',
                'agave': agave_lamports,
                'solanac_prev': prev_lamports,
                'owner': row['owner']
            })
            continue

        if agave_data_len != prev_data_len:
            mismatches.append({
                'pubkey': pubkey,
                'field': 'data_len',
                'agave': agave_data_len,
                'solanac_prev': prev_data_len,
                'owner': row['owner']
            })
            continue

        # For accounts with data, compare data hash against prev binary dump
        if prev_data_len > 0 and agave_val is not None:
            prev_dump = None
            for prefix in ['solanac_sysvar_prev', 'solanac_vote_prev', 'solanac_acct_prev']:
                candidate = os.path.join(DUMP_DIR, f"{prefix}_{SLOT}_{pubkey}.bin")
                if os.path.exists(candidate):
                    prev_dump = candidate
                    break

            if prev_dump:
                with open(prev_dump, 'rb') as f:
                    prev_data = f.read()
                prev_data_hash = hashlib.sha256(prev_data).hexdigest()[:16]

                if prev_data_hash != agave_data_hash:
                    mismatches.append({
                        'pubkey': pubkey,
                        'field': 'data_hash',
                        'agave': agave_data_hash,
                        'solanac_prev': prev_data_hash,
                        'owner': row['owner'],
                        'data_len': prev_data_len
                    })
                    continue

        matches += 1

    print(f"\n=== Results ===")
    print(f"Matches: {matches}")
    print(f"Mismatches: {len(mismatches)}")
    print(f"Errors: {errors}")

    if mismatches:
        print(f"\n=== Mismatches (first 20) ===")
        from collections import Counter
        by_field = Counter(m['field'] for m in mismatches)
        print(f"By field: {dict(by_field)}")
        for m in mismatches[:20]:
            print(f"  {m['pubkey'][:16]}... field={m['field']} agave={m.get('agave')} solanac={m.get('solanac_prev')} owner={m.get('owner','?')[:16]}...")
    else:
        print("\nAll prev states match Agave parent bank!")

if __name__ == '__main__':
    main()
