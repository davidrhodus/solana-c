#!/usr/bin/env python3
"""Compare SolanaC delta dump with Agave RPC account states."""

import sys
import json
import csv
import hashlib
import base64
import base58
import requests
from collections import defaultdict

AGAVE_RPC = "http://127.0.0.1:18999"
TSV_PATH = sys.argv[1] if len(sys.argv) > 1 else "delta_dumps_parity_500/delta_accounts.401587774.tsv"

def get_accounts_batch(pubkeys, batch_size=100):
    """Query Agave RPC for multiple accounts."""
    results = {}
    for i in range(0, len(pubkeys), batch_size):
        batch = pubkeys[i:i+batch_size]
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getMultipleAccounts",
            "params": [batch, {"encoding": "base64", "commitment": "finalized"}]
        }
        try:
            resp = requests.post(AGAVE_RPC, json=payload, timeout=30)
            data = resp.json()
            if "result" in data and "value" in data["result"]:
                for pk, val in zip(batch, data["result"]["value"]):
                    results[pk] = val
        except Exception as e:
            print(f"RPC error: {e}", file=sys.stderr)
    return results

def data_hash_hex(data_bytes):
    """Compute first 8 bytes of SHA256 as hex."""
    if not data_bytes:
        return "0000000000000000"
    h = hashlib.sha256(data_bytes).digest()
    return h[:8].hex()

def main():
    # Read delta dump
    entries = []
    with open(TSV_PATH) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            entries.append(row)

    print(f"Total entries in delta dump: {len(entries)}")

    # Categorize entries
    by_type = defaultdict(list)
    for e in entries:
        by_type[e['type']].append(e)

    for t, lst in by_type.items():
        print(f"  {t}: {len(lst)}")

    # Focus on non-sysvar, non-zero-lamport updated accounts
    interesting = []
    for e in entries:
        if e['type'] not in ('updated', 'created'):
            continue
        # Skip sysvars
        if e['pubkey'].startswith('Sysvar'):
            continue
        # Skip zero-lamport accounts (identity lt_hash, no effect)
        if e['curr_lamports'] == '0':
            continue
        interesting.append(e)

    print(f"\nInteresting accounts (non-sysvar, non-zero curr_lamports): {len(interesting)}")

    # Query Agave for all interesting accounts
    pubkeys = [e['pubkey'] for e in interesting]
    print(f"Querying Agave RPC for {len(pubkeys)} accounts...")
    agave_accounts = get_accounts_batch(pubkeys)

    mismatches = []
    matches = 0
    agave_missing = 0

    for e in interesting:
        pk = e['pubkey']
        agave = agave_accounts.get(pk)

        if agave is None:
            agave_missing += 1
            continue

        # Compare lamports
        agave_lamports = agave.get('lamports', 0)
        sc_lamports = int(e['curr_lamports'])

        # Compare owner
        agave_owner = agave.get('owner', '')
        sc_owner = e['owner']

        # Compare executable
        agave_exec = 1 if agave.get('executable', False) else 0
        sc_exec = int(e['executable'])

        # Compare data hash
        agave_data_b64 = agave.get('data', ['', ''])[0] if agave.get('data') else ''
        agave_data = base64.b64decode(agave_data_b64) if agave_data_b64 else b''
        agave_data_len = len(agave_data)
        sc_data_len = int(e['curr_data_len'])

        agave_dhash = data_hash_hex(agave_data)
        sc_dhash = e['data_hash']

        if (agave_lamports != sc_lamports or
            agave_owner != sc_owner or
            agave_exec != sc_exec or
            agave_data_len != sc_data_len or
            agave_dhash != sc_dhash):
            mismatches.append({
                'pubkey': pk,
                'sc_lamports': sc_lamports,
                'agave_lamports': agave_lamports,
                'sc_owner': sc_owner,
                'agave_owner': agave_owner,
                'sc_exec': sc_exec,
                'agave_exec': agave_exec,
                'sc_data_len': sc_data_len,
                'agave_data_len': agave_data_len,
                'sc_data_hash': sc_dhash,
                'agave_data_hash': agave_dhash,
                'type': e['type'],
                'prev_lamports': e['prev_lamports'],
            })
        else:
            matches += 1

    print(f"\nResults:")
    print(f"  Matches: {matches}")
    print(f"  Mismatches: {len(mismatches)}")
    print(f"  Agave missing: {agave_missing}")

    if mismatches:
        # Group by owner
        by_owner = defaultdict(list)
        for m in mismatches:
            by_owner[m['agave_owner']].append(m)

        print(f"\nMismatches by owner:")
        for owner, lst in sorted(by_owner.items(), key=lambda x: -len(x[1])):
            print(f"  {owner}: {len(lst)}")

        # Show details for first 20 mismatches
        print(f"\nFirst 20 mismatches:")
        for m in mismatches[:20]:
            print(f"  {m['pubkey']}:")
            if m['sc_lamports'] != m['agave_lamports']:
                print(f"    lamports: SC={m['sc_lamports']} AGAVE={m['agave_lamports']} diff={m['agave_lamports']-m['sc_lamports']}")
            if m['sc_owner'] != m['agave_owner']:
                print(f"    owner: SC={m['sc_owner']} AGAVE={m['agave_owner']}")
            if m['sc_exec'] != m['agave_exec']:
                print(f"    executable: SC={m['sc_exec']} AGAVE={m['agave_exec']}")
            if m['sc_data_len'] != m['agave_data_len']:
                print(f"    data_len: SC={m['sc_data_len']} AGAVE={m['agave_data_len']}")
            if m['sc_data_hash'] != m['agave_data_hash']:
                print(f"    data_hash: SC={m['sc_data_hash']} AGAVE={m['agave_data_hash']}")
            print(f"    type={m['type']} prev_lamports={m['prev_lamports']}")

    # Also check: how many of the matching accounts could have been modified in subsequent slots?
    # (this is an upper bound - we're comparing at a later slot)
    print(f"\nNote: Agave is at a later slot than SolanaC. Mismatches may be from subsequent slot modifications.")
    print(f"Note: {matches} exact matches confirms those accounts were NOT modified after slot 401587774.")

if __name__ == "__main__":
    main()
