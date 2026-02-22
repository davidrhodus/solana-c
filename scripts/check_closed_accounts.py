#!/usr/bin/env python3
"""Check accounts that SolanaC closed but Agave didn't."""
import sys, json, csv, requests
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

    # Find all accounts where SolanaC set lamports to 0 (closures)
    closed_accounts = [e for e in entries if e['curr_lamports'] == '0' and e['prev_lamports'] != '0']
    print(f"Accounts closed by SolanaC (lamports went to 0): {len(closed_accounts)}")

    pubkeys = [e['pubkey'] for e in closed_accounts]
    agave = get_accounts_batch(pubkeys)

    # Check which ones Agave still has open
    wrongly_closed = []
    for e in closed_accounts:
        pk = e['pubkey']
        a = agave.get(pk)
        if a is not None and a.get('lamports', 0) > 0:
            wrongly_closed.append((e, a))

    print(f"Accounts SolanaC closed but Agave still has open: {len(wrongly_closed)}")
    for e, a in wrongly_closed:
        print(f"  {e['pubkey']}:")
        print(f"    SC: prev_lamports={e['prev_lamports']} → curr_lamports=0 (CLOSED)")
        print(f"    Agave: lamports={a['lamports']} owner={a['owner']} data_len={a.get('space', len(a.get('data',['',''])[0]))}")
        print(f"    SC prev_owner={e.get('prev_owner')} curr_owner={e['owner']}")

    # Also check ALL accounts with curr_lamports=0 in the delta (including zero→zero)
    zero_accounts = [e for e in entries if e['curr_lamports'] == '0']
    print(f"\nTotal accounts with curr_lamports=0: {len(zero_accounts)}")
    print(f"  created (0→0): {sum(1 for e in zero_accounts if e['type']=='created')}")
    print(f"  updated (X→0): {sum(1 for e in zero_accounts if e['type']=='updated' and e['prev_lamports']!='0')}")
    print(f"  updated (0→0): {sum(1 for e in zero_accounts if e['type']=='updated' and e['prev_lamports']=='0')}")
    print(f"  removed: {sum(1 for e in zero_accounts if e['type']=='removed')}")

    # Check REVERSE: accounts Agave closed but SolanaC didn't
    # (accounts that SolanaC has with non-zero lamports but Agave has NULL or zero)
    # This is harder to detect without Agave's delta, but we can check accounts with
    # large lamport discrepancies
    print("\n=== Accounts with large lamport difference (>10000) ===")
    all_pks = [e['pubkey'] for e in entries if e['curr_lamports'] != '0']
    all_agave = get_accounts_batch(all_pks)
    big_diffs = []
    for e in entries:
        if e['curr_lamports'] == '0':
            continue
        pk = e['pubkey']
        a = all_agave.get(pk)
        if a is None:
            continue
        sc_lam = int(e['curr_lamports'])
        agave_lam = a.get('lamports', 0)
        diff = abs(agave_lam - sc_lam)
        if diff > 10000 and agave_lam > 0:
            big_diffs.append((e, a, diff, agave_lam - sc_lam))

    big_diffs.sort(key=lambda x: -x[2])
    print(f"Found {len(big_diffs)} accounts with >10000 lamport difference")
    for e, a, diff, signed_diff in big_diffs[:20]:
        print(f"  {e['pubkey']}: SC={e['curr_lamports']} AGAVE={a['lamports']} diff={signed_diff}")
        print(f"    owner: SC={e['owner']} AGAVE={a['owner']}")

if __name__ == "__main__":
    main()
