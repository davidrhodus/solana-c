#!/usr/bin/env python3
"""Verify per-account lt_hash computation against TSV first-16-byte prefix."""

import struct
import csv
import os
import blake3
import base58

DUMP_DIR = "/home/ubuntu/solana-c/agave-reptest/delta_dumps"
SLOT = 400986229

def compute_account_lt_hash(lamports, data, executable, owner_bytes, pubkey_bytes):
    if lamports == 0:
        return bytes(2048)
    buf = struct.pack("<Q", lamports) + data + struct.pack("B", 1 if executable else 0) + owner_bytes + pubkey_bytes
    h = blake3.blake3(buf)
    return h.digest(length=2048)

def main():
    tsv_path = f"{DUMP_DIR}/delta_accounts.{SLOT}.tsv"
    with open(tsv_path, "r") as f:
        reader = csv.DictReader(f, delimiter="\t")
        accounts = list(reader)

    mismatches_curr = 0
    mismatches_prev = 0
    checked_curr = 0
    checked_prev = 0

    for idx, acct in enumerate(accounts[:50]):  # Check first 50
        pk = acct["pubkey"]
        pk_bytes = base58.b58decode(pk)
        owner_bytes = base58.b58decode(acct["owner"])
        executable = int(acct["executable"])

        # Check curr
        curr_lamports = int(acct["curr_lamports"])
        curr_data_len = int(acct["curr_data_len"])
        if curr_data_len > 0:
            owner = acct["owner"]
            if owner == "Sysvar1111111111111111111111111111111111111":
                prefix = "solanac_sysvar"
            elif owner == "Vote111111111111111111111111111111111111111":
                prefix = "solanac_vote"
            else:
                prefix = "solanac_acct"
            bin_path = f"{DUMP_DIR}/{prefix}_{SLOT}_{pk}.bin"
            if os.path.exists(bin_path):
                with open(bin_path, "rb") as f:
                    data = f.read()
            else:
                print(f"  {pk}: MISSING curr binary {bin_path}")
                continue
        else:
            data = b""

        curr_lth = compute_account_lt_hash(curr_lamports, data, executable, owner_bytes, pk_bytes)
        tsv_prefix = acct["curr_lthash"]
        computed_prefix = curr_lth[:16].hex()
        checked_curr += 1
        if computed_prefix != tsv_prefix:
            mismatches_curr += 1
            print(f"  CURR MISMATCH {pk}")
            print(f"    computed: {computed_prefix}")
            print(f"    tsv:      {tsv_prefix}")
            print(f"    lamports={curr_lamports} data_len={curr_data_len} exec={executable}")
            for e in [0, 1]:
                lth = compute_account_lt_hash(curr_lamports, data, e, owner_bytes, pk_bytes)
                p = lth[:16].hex()
                if p == tsv_prefix:
                    print(f"    -> MATCHES with executable={e}!")

        # Check prev
        prev_lamports = int(acct["prev_lamports"])
        prev_data_len = int(acct["prev_data_len"])
        if prev_data_len > 0:
            if acct["owner"] == "Sysvar1111111111111111111111111111111111111":
                prefix = "solanac_sysvar"
            elif acct["owner"] == "Vote111111111111111111111111111111111111111":
                prefix = "solanac_vote"
            else:
                prefix = "solanac_acct"
            bin_path = f"{DUMP_DIR}/{prefix}_prev_{SLOT}_{pk}.bin"
            if os.path.exists(bin_path):
                with open(bin_path, "rb") as f:
                    prev_data = f.read()
            else:
                checked_prev += 1
                continue
        else:
            prev_data = b""

        prev_lth = compute_account_lt_hash(prev_lamports, prev_data, executable, owner_bytes, pk_bytes)
        tsv_prev_prefix = acct["prev_lthash"]
        computed_prev_prefix = prev_lth[:16].hex()
        checked_prev += 1
        if computed_prev_prefix != tsv_prev_prefix:
            mismatches_prev += 1
            print(f"  PREV MISMATCH {pk}")
            print(f"    computed: {computed_prev_prefix}")
            print(f"    tsv:      {tsv_prev_prefix}")
            print(f"    lamports={prev_lamports} data_len={prev_data_len} exec={executable}")

    print(f"\nCurr: {mismatches_curr}/{checked_curr} mismatches")
    print(f"Prev: {mismatches_prev}/{checked_prev} mismatches")

if __name__ == "__main__":
    main()
