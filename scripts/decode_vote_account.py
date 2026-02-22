#!/usr/bin/env python3
"""
Decode and compare prev vs curr vote account binary data.
Shows field-by-field differences.
"""
import os
import sys
import struct
import hashlib

DUMP_DIR = "/home/ubuntu/solana-c/delta_dumps_parity23"
SLOT = 400585392

def decode_vote_state_v2(data):
    """Decode VoteState version 2 (Current) bincode format."""
    offset = 0
    result = {}

    # Version tag (u32)
    version = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    result['version'] = version

    if version != 2:
        result['error'] = f'Not version 2 (got {version})'
        return result

    # node_pubkey (32 bytes)
    result['node_pubkey'] = data[offset:offset+32].hex()
    offset += 32

    # authorized_withdrawer (32 bytes)
    result['authorized_withdrawer'] = data[offset:offset+32].hex()
    offset += 32

    # commission (u8)
    result['commission'] = data[offset]
    offset += 1

    # votes: Vec<LandedVote> - length as u64, then LandedVote entries
    votes_len = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    result['votes_len'] = votes_len

    votes = []
    for i in range(votes_len):
        latency = data[offset]
        offset += 1
        slot = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        conf = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        votes.append({'latency': latency, 'slot': slot, 'confirmation_count': conf})
    result['votes'] = votes

    # root_slot: Option<u64>
    has_root = data[offset]
    offset += 1
    if has_root:
        root_slot = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        result['root_slot'] = root_slot
    else:
        result['root_slot'] = None

    # authorized_voters: BTreeMap<Epoch, Pubkey> serialized as Vec<(u64, Pubkey)>
    auth_voters_len = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    auth_voters = []
    for i in range(auth_voters_len):
        epoch = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        pk = data[offset:offset+32].hex()
        offset += 32
        auth_voters.append({'epoch': epoch, 'pubkey': pk})
    result['authorized_voters'] = auth_voters

    # prior_voters: CircBuf<(Pubkey, Epoch, Epoch)> - fixed size 32 entries
    prior_voters = []
    for i in range(32):
        pk = data[offset:offset+32].hex()
        offset += 32
        start_epoch = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        end_epoch = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        prior_voters.append({'pubkey': pk, 'start': start_epoch, 'end': end_epoch})
    result['prior_voters'] = prior_voters

    prior_voters_idx = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    result['prior_voters_idx'] = prior_voters_idx

    prior_voters_is_empty = data[offset]
    offset += 1
    result['prior_voters_is_empty'] = prior_voters_is_empty

    # epoch_credits: Vec<(Epoch, u64, u64)>
    epoch_credits_len = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    epoch_credits = []
    for i in range(epoch_credits_len):
        epoch = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        credits = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        prev_credits = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        epoch_credits.append({'epoch': epoch, 'credits': credits, 'prev_credits': prev_credits})
    result['epoch_credits'] = epoch_credits

    # last_timestamp: BlockTimestamp (slot: u64, timestamp: i64)
    ts_slot = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    ts_value = struct.unpack_from('<q', data, offset)[0]
    offset += 8
    result['last_timestamp_slot'] = ts_slot
    result['last_timestamp'] = ts_value

    result['_bytes_consumed'] = offset
    result['_total_bytes'] = len(data)
    result['_trailing_bytes'] = len(data) - offset

    return result

def compare_vote_states(prev, curr, pubkey):
    """Compare two decoded vote states and report differences."""
    diffs = []

    for key in ['version', 'commission', 'root_slot', 'prior_voters_idx',
                'prior_voters_is_empty', 'last_timestamp_slot', 'last_timestamp',
                'node_pubkey', 'authorized_withdrawer', '_trailing_bytes']:
        if prev.get(key) != curr.get(key):
            diffs.append(f"  {key}: {prev.get(key)} -> {curr.get(key)}")

    # Compare votes
    if prev['votes_len'] != curr['votes_len']:
        diffs.append(f"  votes_len: {prev['votes_len']} -> {curr['votes_len']}")

    # Show vote changes
    prev_slots = {v['slot']: v for v in prev.get('votes', [])}
    curr_slots = {v['slot']: v for v in curr.get('votes', [])}

    removed_slots = set(prev_slots.keys()) - set(curr_slots.keys())
    added_slots = set(curr_slots.keys()) - set(prev_slots.keys())

    if removed_slots:
        diffs.append(f"  votes_removed: {sorted(removed_slots)[:5]}{'...' if len(removed_slots)>5 else ''} (n={len(removed_slots)})")
    if added_slots:
        diffs.append(f"  votes_added: {sorted(added_slots)[:5]}{'...' if len(added_slots)>5 else ''} (n={len(added_slots)})")

    # Compare epoch credits
    prev_ec = prev.get('epoch_credits', [])
    curr_ec = curr.get('epoch_credits', [])
    if len(prev_ec) != len(curr_ec):
        diffs.append(f"  epoch_credits_len: {len(prev_ec)} -> {len(curr_ec)}")
    else:
        for i in range(min(len(prev_ec), len(curr_ec))):
            if prev_ec[i] != curr_ec[i]:
                diffs.append(f"  epoch_credits[{i}]: epoch={prev_ec[i]['epoch']} credits={prev_ec[i]['credits']}->{curr_ec[i]['credits']} prev={prev_ec[i]['prev_credits']}->{curr_ec[i]['prev_credits']}")

    # Compare authorized voters
    prev_av = prev.get('authorized_voters', [])
    curr_av = curr.get('authorized_voters', [])
    if prev_av != curr_av:
        diffs.append(f"  authorized_voters changed: {len(prev_av)} -> {len(curr_av)}")

    return diffs

def main():
    import csv
    import glob

    # Read TSV to find vote accounts
    tsv_path = os.path.join(DUMP_DIR, f"delta_accounts.{SLOT}.tsv")
    vote_accounts = []
    with open(tsv_path) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            if row['owner'] == 'Vote111111111111111111111111111111111111111':
                vote_accounts.append(row)

    print(f"Total vote accounts: {len(vote_accounts)}")

    n_checked = 0
    n_errors = 0
    n_trailing_nonzero = 0

    for row in vote_accounts[:20]:  # Check first 20
        pk = row['pubkey']
        curr_path = os.path.join(DUMP_DIR, f"solanac_vote_{SLOT}_{pk}.bin")
        prev_path = os.path.join(DUMP_DIR, f"solanac_vote_prev_{SLOT}_{pk}.bin")

        if not os.path.exists(curr_path) or not os.path.exists(prev_path):
            continue

        with open(curr_path, 'rb') as f:
            curr_data = f.read()
        with open(prev_path, 'rb') as f:
            prev_data = f.read()

        print(f"\n=== {pk[:20]}... ===")
        print(f"  prev_len={len(prev_data)} curr_len={len(curr_data)}")

        prev_state = decode_vote_state_v2(prev_data)
        curr_state = decode_vote_state_v2(curr_data)

        if 'error' in prev_state:
            print(f"  prev decode error: {prev_state['error']}")
            n_errors += 1
            continue
        if 'error' in curr_state:
            print(f"  curr decode error: {curr_state['error']}")
            n_errors += 1
            continue

        print(f"  prev: version={prev_state['version']} votes={prev_state['votes_len']} "
              f"root={prev_state['root_slot']} epoch_credits={len(prev_state['epoch_credits'])} "
              f"consumed={prev_state['_bytes_consumed']} trailing={prev_state['_trailing_bytes']}")
        print(f"  curr: version={curr_state['version']} votes={curr_state['votes_len']} "
              f"root={curr_state['root_slot']} epoch_credits={len(curr_state['epoch_credits'])} "
              f"consumed={curr_state['_bytes_consumed']} trailing={curr_state['_trailing_bytes']}")

        # Check trailing bytes
        if curr_state['_trailing_bytes'] > 0:
            trailing = curr_data[curr_state['_bytes_consumed']:]
            nonzero = sum(1 for b in trailing if b != 0)
            if nonzero > 0:
                n_trailing_nonzero += 1
                print(f"  WARNING: {nonzero} non-zero trailing bytes!")
                # Show first few non-zero positions
                for j, b in enumerate(trailing):
                    if b != 0 and j < 10:
                        print(f"    trailing[{j}] (offset {curr_state['_bytes_consumed']+j}): 0x{b:02x}")

        diffs = compare_vote_states(prev_state, curr_state, pk)
        if diffs:
            for d in diffs:
                print(d)
        else:
            print("  NO CHANGES (data should have changed!)")

        n_checked += 1

    print(f"\n=== Summary ===")
    print(f"Checked: {n_checked}")
    print(f"Errors: {n_errors}")
    print(f"Trailing non-zero: {n_trailing_nonzero}")

if __name__ == '__main__':
    main()
