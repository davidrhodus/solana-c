#!/usr/bin/env python3
"""Compare confirmed mainnet block data with solana-c delta TSV.

Cross-references:
1. Transaction success/failure (our results vs confirmed)
2. Fee payer lamport changes (post-tx balances from RPC vs our delta)
3. Account write sets (accounts modified per tx vs our delta accounts)
"""

import json
import sys
import os
from collections import defaultdict, Counter

DUMP_DIR = "/home/ubuntu/solana-c/delta_dumps_parity23"
BLOCK_FILE = os.path.join(DUMP_DIR, "block_400585392.json")
DELTA_TSV = os.path.join(DUMP_DIR, "delta_accounts.400585392.tsv")

def load_block():
    with open(BLOCK_FILE) as f:
        return json.load(f)

def load_delta_tsv():
    accounts = {}
    with open(DELTA_TSV) as f:
        header = f.readline().strip().split('\t')
        for line in f:
            fields = line.strip().split('\t')
            row = dict(zip(header, fields))
            accounts[row['pubkey']] = row
    return accounts

def main():
    block = load_block()
    delta = load_delta_tsv()

    print(f"Block: slot={400585392}, txs={len(block['transactions'])}")
    print(f"Delta: {len(delta)} accounts")

    # Extract all writable accounts from the block and their net changes
    # postBalances/preBalances align with accountKeys
    writable_accounts = defaultdict(lambda: {'pre_lamports': 0, 'post_lamports': 0, 'txs': 0})

    tx_results_match = 0
    tx_results_mismatch = 0

    fee_payers = set()
    all_writable_from_block = set()

    for i, tx in enumerate(block['transactions']):
        meta = tx['meta']

        # Get account keys (including loaded addresses for v0 txs)
        if isinstance(tx['transaction'], dict):
            msg = tx['transaction']['message']
            account_keys = msg.get('accountKeys', [])
            # Add loaded addresses (for versioned txs)
            if 'loadedAddresses' in meta:
                loaded = meta['loadedAddresses']
                account_keys += loaded.get('writable', [])
                account_keys += loaded.get('readonly', [])
        else:
            account_keys = []

        if not account_keys:
            continue

        pre_balances = meta['preBalances']
        post_balances = meta['postBalances']
        fee = meta['fee']
        err = meta['err']

        # Fee payer is always index 0
        fee_payer = account_keys[0]
        fee_payers.add(fee_payer)

        # Track writable accounts from pre/post token balances
        for j, (pre, post) in enumerate(zip(pre_balances, post_balances)):
            if pre != post:
                pk = account_keys[j] if j < len(account_keys) else f"unknown_{j}"
                all_writable_from_block.add(pk)
                writable_accounts[pk]['pre_lamports'] = pre  # last tx wins
                writable_accounts[pk]['post_lamports'] = post
                writable_accounts[pk]['txs'] += 1

    print(f"\nFee payers: {len(fee_payers)}")
    print(f"Accounts with lamport changes in block: {len(all_writable_from_block)}")

    # Compare with our delta
    # Check: accounts in block but NOT in our delta
    block_not_in_delta = all_writable_from_block - set(delta.keys())
    delta_not_in_block = set(delta.keys()) - all_writable_from_block

    # Some accounts in our delta but not in block's writable: sysvars, vote accounts modified by fees, etc.
    # Sysvars
    sysvars_in_delta = {pk for pk, row in delta.items() if row['owner'].startswith('Sysvar')}
    vote_in_delta = {pk for pk, row in delta.items() if row['owner'].startswith('Vote1')}
    regular_in_delta = set(delta.keys()) - sysvars_in_delta - vote_in_delta

    print(f"\nDelta breakdown:")
    print(f"  Sysvars: {len(sysvars_in_delta)}")
    print(f"  Vote accounts: {len(vote_in_delta)}")
    print(f"  Regular accounts: {len(regular_in_delta)}")

    print(f"\nAccounts in block's writable but NOT in our delta: {len(block_not_in_delta)}")
    if block_not_in_delta:
        for pk in sorted(block_not_in_delta)[:20]:
            w = writable_accounts[pk]
            print(f"  {pk[:32]}... pre={w['pre_lamports']} post={w['post_lamports']} diff={w['post_lamports']-w['pre_lamports']}")

    print(f"\nAccounts in our delta but NOT in block's writable: {len(delta_not_in_block)}")
    # This is normal for sysvars and vote accounts (they change at slot level)
    non_sysvar_delta_not_in_block = delta_not_in_block - sysvars_in_delta
    print(f"  Non-sysvar: {len(non_sysvar_delta_not_in_block)}")

    # For vote accounts in delta not in block: they were modified by fee distribution
    vote_not_in_block = non_sysvar_delta_not_in_block & vote_in_delta
    regular_not_in_block = non_sysvar_delta_not_in_block - vote_not_in_block
    print(f"  Vote (fee distribution): {len(vote_not_in_block)}")
    print(f"  Regular (unexpected!): {len(regular_not_in_block)}")
    if regular_not_in_block:
        for pk in sorted(regular_not_in_block)[:20]:
            row = delta[pk]
            print(f"    {pk[:32]}... prev_lam={row['prev_lamports']} curr_lam={row['curr_lamports']} data_len={row['curr_data_len']} owner={row['owner'][:16]}...")

    # For accounts in BOTH block and delta, compare lamport changes
    common = all_writable_from_block & set(delta.keys())
    lamport_mismatches = []
    lamport_matches = 0
    for pk in common:
        w = writable_accounts[pk]
        d = delta[pk]
        # Our delta tracks overall (not per-tx) changes.
        # The block's postBalances is the LAST tx's post-balance, but an account
        # might be written by multiple txs.
        # Our delta shows final_lamports = curr_lamports
        our_final = int(d['curr_lamports'])
        block_final = w['post_lamports']
        if our_final != block_final:
            lamport_mismatches.append((pk, our_final, block_final))
        else:
            lamport_matches += 1

    print(f"\nLamport comparison (accounts in both block and delta):")
    print(f"  Common accounts: {len(common)}")
    print(f"  Matches: {lamport_matches}")
    print(f"  Mismatches: {len(lamport_mismatches)}")
    if lamport_mismatches:
        print(f"  First 20 mismatches:")
        for pk, ours, theirs in lamport_mismatches[:20]:
            row = delta[pk]
            print(f"    {pk[:32]}... ours={ours} rpc={theirs} diff={ours-theirs} owner={row['owner'][:16]}...")

    # Check transaction success/failure counts
    confirmed_success = sum(1 for tx in block['transactions'] if tx['meta']['err'] is None)
    confirmed_failed = sum(1 for tx in block['transactions'] if tx['meta']['err'] is not None)
    print(f"\nTransaction counts:")
    print(f"  Confirmed: {confirmed_success} success, {confirmed_failed} failed, total={confirmed_success+confirmed_failed}")

    # Check incinerator account
    INCINERATOR = "1nc1nerator11111111111111111111111111111111"
    if INCINERATOR in delta:
        inc = delta[INCINERATOR]
        print(f"\nIncinerator: prev={inc['prev_lamports']} curr={inc['curr_lamports']} type={inc['type']}")
    elif INCINERATOR in all_writable_from_block:
        w = writable_accounts[INCINERATOR]
        print(f"\nIncinerator in block but not delta: pre={w['pre_lamports']} post={w['post_lamports']}")
    else:
        print(f"\nIncinerator: not present in either block or delta")

    # Check for created/removed accounts
    created = [pk for pk, row in delta.items() if row['type'] == 'created']
    removed = [pk for pk, row in delta.items() if row['type'] == 'removed']
    print(f"\nAccount lifecycle:")
    print(f"  Created: {len(created)}")
    print(f"  Removed: {len(removed)}")
    print(f"  Updated: {len(delta) - len(created) - len(removed)}")

    # For created accounts, check if they appear in block postBalances
    for pk in created[:5]:
        row = delta[pk]
        in_block = pk in all_writable_from_block
        print(f"  Created: {pk[:32]}... lam={row['curr_lamports']} data_len={row['curr_data_len']} in_block={in_block}")

    # Check fee distribution: look at vote accounts that gained lamports
    vote_gained = [(pk, int(row['curr_lamports']) - int(row['prev_lamports']))
                   for pk, row in delta.items()
                   if row['owner'].startswith('Vote1') and int(row['curr_lamports']) > int(row['prev_lamports'])]
    total_fees_distributed = sum(gain for _, gain in vote_gained)
    print(f"\nFee distribution:")
    print(f"  Vote accounts that gained lamports: {len(vote_gained)}")
    print(f"  Total fees distributed: {total_fees_distributed}")

    # Total fees from block
    total_fees = sum(tx['meta']['fee'] for tx in block['transactions'])
    total_base_fees = sum(5000 for tx in block['transactions'])  # assuming 5000 per signature
    total_priority_fees = total_fees - total_base_fees
    burn = (total_base_fees * 50) // 100
    expected_distribution = total_priority_fees + (total_base_fees - burn)
    print(f"  Total fees in block: {total_fees}")
    print(f"  Expected base fees: {total_base_fees} (5000 * {len(block['transactions'])})")
    print(f"  Priority fees: {total_priority_fees}")
    print(f"  Expected burn: {burn}")
    print(f"  Expected distribution: {expected_distribution}")

    # Compute actual signature count (not just tx count)
    total_sigs = 0
    for tx in block['transactions']:
        if isinstance(tx['transaction'], dict):
            total_sigs += len(tx['transaction'].get('signatures', []))
        else:
            total_sigs += 1
    print(f"  Total signatures: {total_sigs}")
    print(f"  Expected base fees (sigs*5000): {total_sigs * 5000}")

if __name__ == "__main__":
    main()
