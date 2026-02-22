#!/usr/bin/env python3
"""Compare SolanaC delta dump accounts against Agave's RPC.

Usage: python3 compare_agave_accounts.py <delta_tsv> [agave_rpc_url]

Reads the SolanaC delta dump TSV, queries each account from Agave's RPC,
and reports differences in lamports, data_len, data_hash, executable, owner.
"""

import csv
import json
import subprocess
import hashlib
import base64
import sys
import time

def query_agave_account(rpc_url, pubkey):
    """Query Agave RPC for account info."""
    payload = json.dumps({
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'getAccountInfo',
        'params': [pubkey, {'encoding': 'base64', 'commitment': 'processed'}]
    })
    try:
        r = subprocess.run(
            ['curl', '-s', '--max-time', '5', '-X', 'POST', rpc_url,
             '-H', 'Content-Type: application/json', '-d', payload],
            capture_output=True, text=True, timeout=10
        )
        d = json.loads(r.stdout)
        v = d['result']['value']
        if v is None:
            return None
        data = base64.b64decode(v['data'][0])
        return {
            'lamports': v['lamports'],
            'data_len': len(data),
            'data_hash': hashlib.sha256(data).hexdigest()[:16],
            'executable': v['executable'],
            'owner': v['owner'],
            'rent_epoch': v.get('rentEpoch', 0),
        }
    except Exception as e:
        return {'error': str(e)}

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <delta_tsv> [agave_rpc_url]")
        sys.exit(1)

    delta_tsv = sys.argv[1]
    rpc_url = sys.argv[2] if len(sys.argv) > 2 else 'http://127.0.0.1:18999'

    # Read delta dump
    accounts = []
    with open(delta_tsv) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            accounts.append(row)

    print(f"Loaded {len(accounts)} accounts from {delta_tsv}")
    print(f"Querying Agave RPC at {rpc_url}...")
    print()

    diffs = []
    missing_in_agave = []
    extra_in_agave = []
    matches = 0
    errors = 0

    for i, acct in enumerate(accounts):
        pk = acct['pubkey']
        if i % 100 == 0:
            print(f"  Progress: {i}/{len(accounts)} ({matches} match, {len(diffs)} diff, {errors} error)", end='\r')

        agave = query_agave_account(rpc_url, pk)
        if agave is None:
            # Account doesn't exist in Agave
            if acct['type'] == 'removed':
                matches += 1  # Both agree it's removed
            else:
                missing_in_agave.append(acct)
            continue

        if 'error' in agave:
            errors += 1
            continue

        # Compare with SolanaC's curr state
        sc_lamports = int(acct['curr_lamports'])
        sc_data_len = int(acct['curr_data_len'])
        sc_data_hash = acct['data_hash']
        sc_executable = int(acct['executable'])

        diff_fields = []
        if sc_lamports != agave['lamports']:
            diff_fields.append(f"lamports: sc={sc_lamports} ag={agave['lamports']}")
        if sc_data_len != agave['data_len']:
            diff_fields.append(f"data_len: sc={sc_data_len} ag={agave['data_len']}")
        if sc_data_hash != agave['data_hash'] and sc_data_hash != '0000000000000000':
            diff_fields.append(f"data_hash: sc={sc_data_hash} ag={agave['data_hash']}")
        if sc_executable != (1 if agave['executable'] else 0):
            diff_fields.append(f"executable: sc={sc_executable} ag={agave['executable']}")

        if diff_fields:
            diffs.append({
                'pubkey': pk,
                'owner': acct['owner'],
                'type': acct['type'],
                'diffs': diff_fields,
            })
        else:
            matches += 1

        # Small delay to avoid overwhelming RPC
        if i % 50 == 49:
            time.sleep(0.1)

    print(f"\n\nResults: {matches} match, {len(diffs)} diff, {len(missing_in_agave)} missing, {errors} error")
    print()

    if diffs:
        print("=== DIFFERENT ACCOUNTS ===")
        for d in diffs[:50]:
            print(f"  {d['pubkey'][:20]}... ({d['type']}, owner={d['owner'][:12]}...)")
            for f in d['diffs']:
                print(f"    {f}")
        if len(diffs) > 50:
            print(f"  ... and {len(diffs) - 50} more")
        print()

    if missing_in_agave:
        print("=== ACCOUNTS IN SOLANAC BUT NOT IN AGAVE ===")
        for a in missing_in_agave[:20]:
            print(f"  {a['pubkey'][:20]}... ({a['type']}, lamports={a['curr_lamports']}, owner={a['owner'][:12]}...)")
        if len(missing_in_agave) > 20:
            print(f"  ... and {len(missing_in_agave) - 20} more")

if __name__ == '__main__':
    main()
