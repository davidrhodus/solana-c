#!/usr/bin/env python3
"""Find accounts missing in Agave but present in SolanaC delta dump."""
import sys, json, csv, hashlib, base64, requests
from collections import defaultdict

AGAVE_RPC = "http://127.0.0.1:18999"
TSV_PATH = sys.argv[1] if len(sys.argv) > 1 else "delta_dumps_parity_500/delta_accounts.401587774.tsv"

def get_account(pubkey):
    payload = {
        "jsonrpc": "2.0", "id": 1,
        "method": "getAccountInfo",
        "params": [pubkey, {"encoding": "base64", "commitment": "finalized"}]
    }
    resp = requests.post(AGAVE_RPC, json=payload, timeout=30)
    data = resp.json()
    if "result" in data:
        return data["result"]["value"]
    return None

def get_accounts_batch(pubkeys, batch_size=100):
    results = {}
    for i in range(0, len(pubkeys), batch_size):
        batch = pubkeys[i:i+batch_size]
        payload = {
            "jsonrpc": "2.0", "id": 1,
            "method": "getMultipleAccounts",
            "params": [batch, {"encoding": "base64", "commitment": "finalized"}]
        }
        resp = requests.post(AGAVE_RPC, json=payload, timeout=30)
        data = resp.json()
        if "result" in data and "value" in data["result"]:
            for pk, val in zip(batch, data["result"]["value"]):
                results[pk] = val
    return results

def main():
    entries = []
    with open(TSV_PATH) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            entries.append(row)

    # Get ALL accounts (including zero lamport ones)
    all_pubkeys = [e['pubkey'] for e in entries]
    print(f"Querying Agave for ALL {len(all_pubkeys)} accounts...")
    agave_accounts = get_accounts_batch(all_pubkeys)

    # Find accounts where Agave returns None (not found)
    missing_in_agave = []
    for e in entries:
        pk = e['pubkey']
        agave = agave_accounts.get(pk)
        if agave is None:
            missing_in_agave.append(e)

    print(f"\nAccounts missing in Agave (returned NULL): {len(missing_in_agave)}")
    for m in missing_in_agave[:30]:
        print(f"  {m['pubkey']}: type={m['type']} curr_lamports={m['curr_lamports']} prev_lamports={m['prev_lamports']} owner={m['owner']}")

    # Now find accounts where SolanaC has them as "created" but Agave has non-zero data
    # This would indicate the account existed before but SolanaC didn't see it
    created_but_existed = []
    for e in entries:
        if e['type'] != 'created':
            continue
        pk = e['pubkey']
        agave = agave_accounts.get(pk)
        if agave and agave.get('lamports', 0) > 0:
            created_but_existed.append((e, agave))

    if created_but_existed:
        print(f"\nAccounts SolanaC marks as 'created' but Agave has data: {len(created_but_existed)}")
        for e, agave in created_but_existed[:10]:
            print(f"  {e['pubkey']}: SC_curr_lamports={e['curr_lamports']} AGAVE_lamports={agave['lamports']} SC_owner={e['owner']} AGAVE_owner={agave['owner']}")

    # Find accounts where the EXECUTABLE flag differs
    exec_diffs = []
    for e in entries:
        pk = e['pubkey']
        agave = agave_accounts.get(pk)
        if agave is None:
            continue
        sc_exec = int(e['executable'])
        agave_exec = 1 if agave.get('executable', False) else 0
        if sc_exec != agave_exec:
            exec_diffs.append((e, agave))

    if exec_diffs:
        print(f"\nExecutable flag differences: {len(exec_diffs)}")
        for e, agave in exec_diffs[:10]:
            print(f"  {e['pubkey']}: SC_exec={e['executable']} AGAVE_exec={agave.get('executable')} SC_owner={e['owner']}")

    # Find accounts where OWNER differs
    owner_diffs = []
    for e in entries:
        pk = e['pubkey']
        agave = agave_accounts.get(pk)
        if agave is None:
            continue
        if e['owner'] != agave.get('owner', ''):
            owner_diffs.append((e, agave))

    if owner_diffs:
        print(f"\nOwner differences: {len(owner_diffs)}")
        for e, agave in owner_diffs[:10]:
            print(f"  {e['pubkey']}: SC_owner={e['owner']} AGAVE_owner={agave.get('owner')}")

    # For accounts that matched (same state), check if their prev state might be wrong
    # by looking at accounts where prev_lamports seems unusual
    print(f"\n=== Accounts with prev_lamports=0 but type=updated (suspicious) ===")
    for e in entries:
        if e['type'] == 'updated' and e['prev_lamports'] == '0':
            print(f"  {e['pubkey']}: curr_lamports={e['curr_lamports']} owner={e['owner']}")

    print(f"\n=== Accounts with prev_owner != curr_owner (suspicious) ===")
    for e in entries:
        if e['type'] == 'updated' and e.get('prev_owner', '-') != '-' and e.get('prev_owner') != e['owner']:
            print(f"  {e['pubkey']}: prev_owner={e.get('prev_owner')} curr_owner={e['owner']}")

if __name__ == "__main__":
    main()
