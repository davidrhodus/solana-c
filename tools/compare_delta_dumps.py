#!/usr/bin/env python3
"""Compare delta dump TSV files from Agave and solana-c.

Usage: compare_delta_dumps.py <agave_tsv> <solanac_tsv> [<dump_dir_agave> <dump_dir_solanac>]

Compares per-account data between Agave and solana-c delta dumps.
Reports:
- Accounts in Agave but not solana-c (and vice versa)
- Accounts with different lamports, data_len, executable
- Accounts with different data hashes
- Binary data diffs for accounts with different data
"""

import sys
import os
import hashlib

def parse_tsv(path):
    """Parse delta accounts TSV file into dict keyed by pubkey."""
    accounts = {}
    with open(path) as f:
        header = f.readline().strip().split('\t')
        for line in f:
            fields = line.strip().split('\t')
            if len(fields) < 8:
                continue
            pk = fields[0]
            accounts[pk] = {
                'prev_lamports': int(fields[1]),
                'curr_lamports': int(fields[2]),
                'prev_data_len': int(fields[3]),
                'curr_data_len': int(fields[4]),
                'owner': fields[5],
                'type': fields[6],
                'executable': int(fields[7]),
                'data_hash': fields[8] if len(fields) > 8 else '',
                'curr_lthash': fields[9] if len(fields) > 9 else '',
                'prev_lthash': fields[10] if len(fields) > 10 else '',
                'prev_data_hash': fields[11] if len(fields) > 11 else '',
            }
    return accounts

def sha256_file(path):
    """Compute SHA256 of a file, return first 8 bytes as hex."""
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()[:16]

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <agave_tsv> <solanac_tsv> [<agave_data_dir> <solanac_data_dir>]")
        sys.exit(1)

    agave_tsv = sys.argv[1]
    solanac_tsv = sys.argv[2]
    agave_dir = sys.argv[3] if len(sys.argv) > 3 else os.path.dirname(agave_tsv)
    solanac_dir = sys.argv[4] if len(sys.argv) > 4 else os.path.dirname(solanac_tsv)

    agave = parse_tsv(agave_tsv)
    solanac = parse_tsv(solanac_tsv)

    print(f"Agave accounts: {len(agave)}")
    print(f"Solana-C accounts: {len(solanac)}")

    # Find common and unique accounts
    agave_only = set(agave.keys()) - set(solanac.keys())
    solanac_only = set(solanac.keys()) - set(agave.keys())
    common = set(agave.keys()) & set(solanac.keys())

    print(f"Common: {len(common)}")
    print(f"Agave-only: {len(agave_only)}")
    print(f"Solana-C-only: {len(solanac_only)}")

    if agave_only:
        print(f"\nAccounts in Agave but NOT solana-c:")
        for pk in sorted(agave_only):
            a = agave[pk]
            print(f"  {pk}: lam={a['curr_lamports']} dlen={a['curr_data_len']} owner={a['owner']} type={a['type']}")

    if solanac_only:
        print(f"\nAccounts in solana-c but NOT Agave:")
        for pk in sorted(solanac_only):
            s = solanac[pk]
            print(f"  {pk}: lam={s['curr_lamports']} dlen={s['curr_data_len']} owner={s['owner']} type={s['type']}")

    # Compare common accounts
    n_match = 0
    n_lam_diff = 0
    n_dlen_diff = 0
    n_datahash_diff = 0
    n_lthash_diff = 0

    data_diff_accounts = []

    for pk in sorted(common):
        a = agave[pk]
        s = solanac[pk]

        has_diff = False
        diffs = []

        if a['curr_lamports'] != s['curr_lamports']:
            n_lam_diff += 1
            diffs.append(f"lamports: agave={a['curr_lamports']} solanac={s['curr_lamports']}")
            has_diff = True

        if a['curr_data_len'] != s['curr_data_len']:
            n_dlen_diff += 1
            diffs.append(f"data_len: agave={a['curr_data_len']} solanac={s['curr_data_len']}")
            has_diff = True

        if a['data_hash'] and s['data_hash'] and a['data_hash'] != s['data_hash']:
            n_datahash_diff += 1
            diffs.append(f"data_hash: agave={a['data_hash']} solanac={s['data_hash']}")
            has_diff = True
            data_diff_accounts.append(pk)

        if a['curr_lthash'] and s['curr_lthash'] and a['curr_lthash'] != s['curr_lthash']:
            n_lthash_diff += 1
            if not has_diff:
                diffs.append(f"curr_lthash: agave={a['curr_lthash']} solanac={s['curr_lthash']}")
                has_diff = True

        if not has_diff:
            n_match += 1
        else:
            print(f"\nDIFF: {pk} (owner={a['owner']})")
            for d in diffs:
                print(f"  {d}")

    print(f"\n=== Summary ===")
    print(f"Full match: {n_match}")
    print(f"Lamport diff: {n_lam_diff}")
    print(f"Data len diff: {n_dlen_diff}")
    print(f"Data hash diff: {n_datahash_diff}")
    print(f"Lt_hash diff: {n_lthash_diff}")

    # Compare binary data for accounts with different hashes
    if data_diff_accounts and len(sys.argv) > 4:
        print(f"\n=== Binary data comparison ===")
        for pk in data_diff_accounts[:10]:
            # Try to find binary files
            slot = os.path.basename(agave_tsv).split('.')[1] if '.' in os.path.basename(agave_tsv) else ''
            agave_bin = os.path.join(agave_dir, f"agave_acct_{slot}_{pk}.bin")
            # Try various solanac prefixes
            solanac_bin = None
            for prefix in ['solanac_acct', 'solanac_vote', 'solanac_sysvar']:
                candidate = os.path.join(solanac_dir, f"{prefix}_{slot}_{pk}.bin")
                if os.path.exists(candidate):
                    solanac_bin = candidate
                    break

            print(f"\n{pk}:")
            if os.path.exists(agave_bin):
                with open(agave_bin, 'rb') as f:
                    agave_data = f.read()
                print(f"  Agave data: {len(agave_data)} bytes, sha256={hashlib.sha256(agave_data).hexdigest()[:16]}")
            else:
                print(f"  Agave data: NOT FOUND ({agave_bin})")
                agave_data = None

            if solanac_bin:
                with open(solanac_bin, 'rb') as f:
                    solanac_data = f.read()
                print(f"  Solana-C data: {len(solanac_data)} bytes, sha256={hashlib.sha256(solanac_data).hexdigest()[:16]}")
            else:
                print(f"  Solana-C data: NOT FOUND")
                solanac_data = None

            if agave_data and solanac_data:
                if agave_data == solanac_data:
                    print(f"  BINARY MATCH")
                else:
                    # Find first difference
                    min_len = min(len(agave_data), len(solanac_data))
                    first_diff = None
                    diff_count = 0
                    for i in range(min_len):
                        if agave_data[i] != solanac_data[i]:
                            if first_diff is None:
                                first_diff = i
                            diff_count += 1
                    if len(agave_data) != len(solanac_data):
                        diff_count += abs(len(agave_data) - len(solanac_data))
                    print(f"  BINARY DIFF: first_diff_offset={first_diff}, total_diff_bytes={diff_count}")
                    if first_diff is not None:
                        # Show context around first diff
                        start = max(0, first_diff - 4)
                        end = min(min_len, first_diff + 20)
                        print(f"  Agave @{start}: {agave_data[start:end].hex()}")
                        print(f"  SolC  @{start}: {solanac_data[start:end].hex()}")

if __name__ == '__main__':
    main()
