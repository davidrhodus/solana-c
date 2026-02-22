#!/usr/bin/env python3
"""Find accounts where Agave matches SolanaC's PREV state (tx not applied in Agave)."""
import sys, csv, base64, requests
from collections import defaultdict

AGAVE_RPC = "http://127.0.0.1:18999"
TSV_PATH = sys.argv[1] if len(sys.argv) > 1 else "delta_dumps_parity_500/delta_accounts.401587774.tsv"

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

    # Focus on updated accounts (not created)
    updated = [e for e in entries if e['type'] == 'updated' and e['curr_lamports'] != e['prev_lamports']]
    print(f"Updated accounts with lamport changes: {len(updated)}")

    pubkeys = [e['pubkey'] for e in updated]
    agave = get_accounts_batch(pubkeys)

    # For each updated account, check if Agave matches PREV or CURR state
    matches_prev = []  # Agave has the old state -> tx not applied in Agave
    matches_curr = []  # Agave has the new state -> tx applied in both
    matches_neither = []  # Agave has different state -> modified by later slot

    for e in updated:
        pk = e['pubkey']
        a = agave.get(pk)
        prev_lam = int(e['prev_lamports'])
        curr_lam = int(e['curr_lamports'])

        if a is None:
            # Account deleted in Agave
            if curr_lam == 0:
                matches_curr.append(e)
            elif prev_lam == 0:
                matches_prev.append(e)
            else:
                matches_neither.append(e)
            continue

        agave_lam = a.get('lamports', 0)

        if agave_lam == curr_lam:
            matches_curr.append(e)
        elif agave_lam == prev_lam:
            matches_prev.append(e)
        else:
            matches_neither.append(e)

    print(f"\nAgave matches SolanaC CURR (tx applied in both): {len(matches_curr)}")
    print(f"Agave matches SolanaC PREV (tx NOT applied in Agave): {len(matches_prev)}")
    print(f"Agave matches NEITHER (modified by later slot): {len(matches_neither)}")

    if matches_prev:
        print(f"\n=== Accounts where Agave has PREV state (divergent txs) ===")
        by_owner = defaultdict(list)
        for e in matches_prev:
            by_owner[e['owner']].append(e)
        for owner, lst in sorted(by_owner.items(), key=lambda x: -len(x[1])):
            print(f"  {owner}: {len(lst)}")
        print()
        for e in matches_prev[:30]:
            print(f"  {e['pubkey']}: prev={e['prev_lamports']}→curr={e['curr_lamports']} owner={e['owner']} prev_owner={e.get('prev_owner','-')}")

if __name__ == "__main__":
    main()
