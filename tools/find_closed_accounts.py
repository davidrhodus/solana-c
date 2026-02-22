#!/usr/bin/env python3
"""Find accounts closed in a block (pre-balance != 0, post-balance == 0)."""

import json
import sys

BLOCK_FILE = "/home/ubuntu/solana-c/delta_dumps_parity23/block_400585392.json"
DELTA_TSV = "/home/ubuntu/solana-c/delta_dumps_parity23/delta_accounts.400585392.tsv"

def main():
    with open(BLOCK_FILE) as f:
        block = json.load(f)

    closed_accounts = {}  # pubkey -> {pre, post, tx_idx, tx_sig}

    for i, tx in enumerate(block['transactions']):
        meta = tx['meta']
        msg = tx['transaction']['message']
        account_keys = msg.get('accountKeys', [])
        if 'loadedAddresses' in meta:
            loaded = meta['loadedAddresses']
            account_keys += loaded.get('writable', [])
            account_keys += loaded.get('readonly', [])

        pre_balances = meta['preBalances']
        post_balances = meta['postBalances']
        sigs = tx['transaction'].get('signatures', [])
        tx_sig = sigs[0] if sigs else 'unknown'

        for j, (pre, post) in enumerate(zip(pre_balances, post_balances)):
            if pre != 0 and post == 0:
                pk = account_keys[j] if j < len(account_keys) else f"unknown_{j}"
                closed_accounts[pk] = {
                    'pre_lamports': pre,
                    'post_lamports': post,
                    'tx_idx': i,
                    'tx_sig': tx_sig,
                    'err': meta['err'],
                }

    print(f"=== Accounts closed in block 400585392 (pre != 0, post == 0) ===")
    print(f"Found {len(closed_accounts)} closed account(s):\n")

    for pk, info in sorted(closed_accounts.items()):
        print(f"  Pubkey: {pk}")
        print(f"    Pre-balance:  {info['pre_lamports']} lamports")
        print(f"    Post-balance: {info['post_lamports']} lamports")
        print(f"    Tx index:     {info['tx_idx']}")
        print(f"    Tx signature: {info['tx_sig']}")
        print(f"    Tx error:     {info['err']}")
        print()

    # Check if these accounts exist in our delta TSV
    print(f"=== Checking delta_accounts.400585392.tsv ===")
    delta = {}
    with open(DELTA_TSV) as f:
        header = f.readline().strip().split('\t')
        for line in f:
            fields = line.strip().split('\t')
            row = dict(zip(header, fields))
            delta[row['pubkey']] = row

    for pk in sorted(closed_accounts.keys()):
        if pk in delta:
            row = delta[pk]
            print(f"  FOUND in delta: {pk}")
            print(f"    type={row['type']} prev_lam={row['prev_lamports']} curr_lam={row['curr_lamports']}")
            print(f"    owner={row['owner']} data_len={row.get('curr_data_len', 'N/A')}")
        else:
            print(f"  NOT FOUND in delta: {pk}")
    print()

if __name__ == "__main__":
    main()
