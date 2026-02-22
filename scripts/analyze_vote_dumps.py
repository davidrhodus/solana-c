#!/usr/bin/env python3
"""
Analyze vote account binary dumps from solana-c.
Decode VoteState from binary data and compare curr vs prev.
"""
import os
import sys
import struct
import glob
from collections import defaultdict

DUMP_DIR = sys.argv[1] if len(sys.argv) > 1 else "/home/ubuntu/solana-c/delta_dumps_parity22"
SLOT = 400585392

def decode_vote_state_v2(data):
    """Decode VoteState version 2 (current) from bincode bytes."""
    off = 0
    result = {}

    # u32 version tag
    version = struct.unpack_from('<I', data, off)[0]
    off += 4
    result['version'] = version

    if version != 2:
        return None, f"unexpected version {version}"

    # Pubkey node_pubkey (32 bytes)
    result['node_pubkey'] = data[off:off+32].hex()
    off += 32

    # Pubkey authorized_withdrawer (32 bytes)
    result['authorized_withdrawer'] = data[off:off+32].hex()
    off += 32

    # u8 commission
    result['commission'] = data[off]
    off += 1

    # Vec<LandedVote> votes: u64 len, then for each: u8 latency + u64 slot + u32 confirmation_count
    votes_len = struct.unpack_from('<Q', data, off)[0]
    off += 8
    votes = []
    for _ in range(votes_len):
        latency = data[off]
        off += 1
        slot = struct.unpack_from('<Q', data, off)[0]
        off += 8
        conf = struct.unpack_from('<I', data, off)[0]
        off += 4
        votes.append({'latency': latency, 'slot': slot, 'confirmation_count': conf})
    result['votes'] = votes
    result['votes_len'] = votes_len

    # Option<u64> root_slot
    has_root = data[off]
    off += 1
    if has_root:
        root_slot = struct.unpack_from('<Q', data, off)[0]
        off += 8
        result['root_slot'] = root_slot
    else:
        result['root_slot'] = None

    # Vec<(Epoch, Pubkey)> authorized_voters
    av_len = struct.unpack_from('<Q', data, off)[0]
    off += 8
    authorized_voters = []
    for _ in range(av_len):
        epoch = struct.unpack_from('<Q', data, off)[0]
        off += 8
        pk = data[off:off+32].hex()
        off += 32
        authorized_voters.append({'epoch': epoch, 'pubkey': pk})
    result['authorized_voters'] = authorized_voters

    # CircBuf prior_voters: 32 entries of (Pubkey, Epoch, Epoch), then u64 idx, bool is_empty
    prior_voters = []
    for _ in range(32):
        pk = data[off:off+32].hex()
        off += 32
        start_epoch = struct.unpack_from('<Q', data, off)[0]
        off += 8
        end_epoch = struct.unpack_from('<Q', data, off)[0]
        off += 8
        prior_voters.append({'pubkey': pk, 'start_epoch': start_epoch, 'end_epoch': end_epoch})
    result['prior_voters'] = prior_voters
    prior_voters_idx = struct.unpack_from('<Q', data, off)[0]
    off += 8
    prior_voters_is_empty = data[off]
    off += 1
    result['prior_voters_idx'] = prior_voters_idx
    result['prior_voters_is_empty'] = prior_voters_is_empty

    # Vec<(Epoch, u64, u64)> epoch_credits
    ec_len = struct.unpack_from('<Q', data, off)[0]
    off += 8
    epoch_credits = []
    for _ in range(ec_len):
        epoch = struct.unpack_from('<Q', data, off)[0]
        off += 8
        credits = struct.unpack_from('<Q', data, off)[0]
        off += 8
        prev_credits = struct.unpack_from('<Q', data, off)[0]
        off += 8
        epoch_credits.append({'epoch': epoch, 'credits': credits, 'prev_credits': prev_credits})
    result['epoch_credits'] = epoch_credits

    # Slot last_timestamp_slot, i64 last_timestamp
    result['last_timestamp_slot'] = struct.unpack_from('<Q', data, off)[0]
    off += 8
    result['last_timestamp'] = struct.unpack_from('<q', data, off)[0]
    off += 8

    result['_serialized_len'] = off
    return result, None

def compare_vote_states(prev, curr, pubkey):
    """Compare two vote states and return list of differences."""
    diffs = []

    if prev is None or curr is None:
        return ['one or both states failed to decode']

    # Static fields that shouldn't change in a normal vote tx
    for field in ['node_pubkey', 'authorized_withdrawer', 'commission', 'authorized_voters',
                  'prior_voters', 'prior_voters_idx', 'prior_voters_is_empty']:
        if prev.get(field) != curr.get(field):
            diffs.append(f'{field} changed')

    # Vote tower changes (expected)
    if prev['votes'] != curr['votes']:
        diffs.append(f'votes changed: {prev["votes_len"]} -> {curr["votes_len"]}')

    # Root slot changes
    if prev['root_slot'] != curr['root_slot']:
        diffs.append(f'root_slot changed: {prev["root_slot"]} -> {curr["root_slot"]}')

    # Epoch credits changes
    if prev['epoch_credits'] != curr['epoch_credits']:
        # Find specific changes
        prev_ec = {ec['epoch']: ec for ec in prev['epoch_credits']}
        curr_ec = {ec['epoch']: ec for ec in curr['epoch_credits']}

        for epoch in sorted(set(list(prev_ec.keys()) + list(curr_ec.keys()))):
            pe = prev_ec.get(epoch)
            ce = curr_ec.get(epoch)
            if pe != ce:
                diffs.append(f'epoch_credits[{epoch}]: {pe} -> {ce}')

    # Timestamp changes
    if prev['last_timestamp_slot'] != curr['last_timestamp_slot']:
        diffs.append(f'last_timestamp_slot changed: {prev["last_timestamp_slot"]} -> {curr["last_timestamp_slot"]}')
    if prev['last_timestamp'] != curr['last_timestamp']:
        diffs.append(f'last_timestamp changed: {prev["last_timestamp"]} -> {curr["last_timestamp"]}')

    return diffs

def main():
    # Find all vote curr files
    pattern = os.path.join(DUMP_DIR, f"solanac_vote_{SLOT}_*.bin")
    curr_files = sorted(glob.glob(pattern))

    print(f"Found {len(curr_files)} vote account current dumps")

    stats = defaultdict(int)
    issues = []

    # Check data lengths
    data_lens = defaultdict(int)

    for curr_file in curr_files:
        # Extract pubkey from filename
        basename = os.path.basename(curr_file)
        # solanac_vote_400585392_PUBKEY.bin
        parts = basename.replace('.bin', '').split('_', 3)
        pubkey = parts[3] if len(parts) > 3 else 'unknown'

        prev_file = curr_file.replace(f'solanac_vote_{SLOT}_', f'solanac_vote_prev_{SLOT}_')

        with open(curr_file, 'rb') as f:
            curr_data = f.read()

        data_lens[len(curr_data)] += 1

        if not os.path.exists(prev_file):
            stats['no_prev'] += 1
            continue

        with open(prev_file, 'rb') as f:
            prev_data = f.read()

        # Check if data is identical
        if curr_data == prev_data:
            stats['identical'] += 1
            continue

        # Decode both states
        curr_state, curr_err = decode_vote_state_v2(curr_data)
        prev_state, prev_err = decode_vote_state_v2(prev_data)

        if curr_err:
            stats['decode_err'] += 1
            issues.append(f'{pubkey}: curr decode error: {curr_err}')
            continue
        if prev_err:
            stats['decode_err'] += 1
            issues.append(f'{pubkey}: prev decode error: {prev_err}')
            continue

        diffs = compare_vote_states(prev_state, curr_state, pubkey)

        if not diffs:
            stats['decoded_identical'] += 1
        else:
            stats['changed'] += 1

            # Check vote tower invariants
            tower_ok = True
            for i, v in enumerate(curr_state['votes']):
                # Confirmation count should be >= 1
                if v['confirmation_count'] < 1:
                    tower_ok = False
                    issues.append(f'{pubkey}: vote[{i}] conf_count={v["confirmation_count"]} < 1')
                # Slots should be monotonically increasing
                if i > 0 and v['slot'] <= curr_state['votes'][i-1]['slot']:
                    tower_ok = False
                    issues.append(f'{pubkey}: non-monotonic slots at [{i}]: {curr_state["votes"][i-1]["slot"]} >= {v["slot"]}')
                # Confirmation count should be monotonically decreasing from bottom to top
                if i > 0 and v['confirmation_count'] > curr_state['votes'][i-1]['confirmation_count']:
                    pass  # This can happen in normal operation

            # Check serialized length vs data length
            if curr_state['_serialized_len'] != len(curr_data):
                issues.append(f'{pubkey}: serialized_len={curr_state["_serialized_len"]} != data_len={len(curr_data)}')

            # Check trailing bytes are all zero
            if curr_state['_serialized_len'] < len(curr_data):
                trailing = curr_data[curr_state['_serialized_len']:]
                non_zero = sum(1 for b in trailing if b != 0)
                if non_zero > 0:
                    stats['non_zero_trailing'] += 1

    print(f"\nStats:")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v}")

    print(f"\nData length distribution:")
    for l, c in sorted(data_lens.items()):
        print(f"  {l} bytes: {c} accounts")

    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues[:50]:
            print(f"  {issue}")
    else:
        print("\nNo issues found!")

    # Print first few changed vote accounts with details
    print(f"\n=== First 3 changed vote accounts (detailed) ===")
    count = 0
    for curr_file in curr_files:
        if count >= 3:
            break
        basename = os.path.basename(curr_file)
        parts = basename.replace('.bin', '').split('_', 3)
        pubkey = parts[3] if len(parts) > 3 else 'unknown'
        prev_file = curr_file.replace(f'solanac_vote_{SLOT}_', f'solanac_vote_prev_{SLOT}_')

        if not os.path.exists(prev_file):
            continue

        with open(curr_file, 'rb') as f:
            curr_data = f.read()
        with open(prev_file, 'rb') as f:
            prev_data = f.read()

        if curr_data == prev_data:
            continue

        curr_state, _ = decode_vote_state_v2(curr_data)
        prev_state, _ = decode_vote_state_v2(prev_data)

        if curr_state and prev_state:
            print(f"\n--- {pubkey} ---")
            print(f"  Votes: {prev_state['votes_len']} -> {curr_state['votes_len']}")
            if curr_state['votes']:
                print(f"  Latest vote slot: {curr_state['votes'][-1]['slot']}")
            print(f"  Root: {prev_state['root_slot']} -> {curr_state['root_slot']}")

            # Show epoch credits change
            prev_last_ec = prev_state['epoch_credits'][-1] if prev_state['epoch_credits'] else None
            curr_last_ec = curr_state['epoch_credits'][-1] if curr_state['epoch_credits'] else None
            print(f"  Last epoch_credits: {prev_last_ec} -> {curr_last_ec}")

            print(f"  Timestamp: slot {prev_state['last_timestamp_slot']}->{curr_state['last_timestamp_slot']} ts {prev_state['last_timestamp']}->{curr_state['last_timestamp']}")

            # Show serialized length
            print(f"  Serialized len: {curr_state['_serialized_len']} / {len(curr_data)} total")

            # Show first byte difference
            for i in range(min(len(curr_data), len(prev_data))):
                if curr_data[i] != prev_data[i]:
                    print(f"  First diff at byte {i}: {prev_data[i]:02x} -> {curr_data[i]:02x}")
                    break

            count += 1

if __name__ == '__main__':
    main()
