#!/usr/bin/env python3
"""Verify ALL per-account lt_hash computation and reconstruct delta."""

import struct
import csv
import os
import blake3
import base58
import numpy as np

DUMP_DIR = "/home/ubuntu/solana-c/agave-reptest/delta_dumps"
SLOT = 400986229

def compute_account_lt_hash_bytes(lamports, data, executable, owner_bytes, pubkey_bytes):
    if lamports == 0:
        return bytes(2048)
    buf = struct.pack("<Q", lamports) + data + struct.pack("B", 1 if executable else 0) + owner_bytes + pubkey_bytes
    h = blake3.blake3(buf)
    return h.digest(length=2048)

def load_lt_hash(path):
    with open(path, "rb") as f:
        return np.frombuffer(f.read(), dtype=np.uint16).copy()

def lt_hash_checksum(arr):
    h = blake3.blake3(arr.tobytes())
    return base58.b58encode(h.digest()).decode()

def main():
    tsv_path = f"{DUMP_DIR}/delta_accounts.{SLOT}.tsv"
    with open(tsv_path, "r") as f:
        reader = csv.DictReader(f, delimiter="\t")
        accounts = list(reader)

    base = load_lt_hash(f"{DUMP_DIR}/lt_hash_base.{SLOT}.bin")
    final = load_lt_hash(f"{DUMP_DIR}/lt_hash_final.{SLOT}.bin")
    
    print(f"Base checksum:  {lt_hash_checksum(base)}")
    print(f"Final checksum: {lt_hash_checksum(final)}")
    
    # Compute total delta from per-account contributions
    total_delta = np.zeros(1024, dtype=np.uint16)
    mismatches = 0
    skipped = 0
    
    for idx, acct in enumerate(accounts):
        pk = acct["pubkey"]
        pk_bytes = base58.b58decode(pk)
        owner_bytes = base58.b58decode(acct["owner"])
        executable = int(acct["executable"])
        owner = acct["owner"]
        
        # Compute curr lt_hash
        curr_lamports = int(acct["curr_lamports"])
        curr_data_len = int(acct["curr_data_len"])
        if curr_data_len > 0:
            if owner == "Sysvar1111111111111111111111111111111111111":
                prefix = "solanac_sysvar"
            elif owner == "Vote111111111111111111111111111111111111111":
                prefix = "solanac_vote"
            else:
                prefix = "solanac_acct"
            bin_path = f"{DUMP_DIR}/{prefix}_{SLOT}_{pk}.bin"
            if os.path.exists(bin_path):
                with open(bin_path, "rb") as f:
                    curr_data = f.read()
            else:
                skipped += 1
                continue
        else:
            curr_data = b""
            
        curr_lth_bytes = compute_account_lt_hash_bytes(curr_lamports, curr_data, executable, owner_bytes, pk_bytes)
        curr_lth = np.frombuffer(curr_lth_bytes, dtype=np.uint16)
        
        # Verify curr prefix
        tsv_prefix = acct["curr_lthash"]
        computed_prefix = curr_lth_bytes[:16].hex()
        if computed_prefix != tsv_prefix:
            mismatches += 1
            print(f"  CURR MISMATCH #{idx}: {pk} computed={computed_prefix} tsv={tsv_prefix}")
        
        # Compute prev lt_hash
        prev_lamports = int(acct["prev_lamports"])
        prev_data_len = int(acct["prev_data_len"])
        if prev_data_len > 0:
            if owner == "Sysvar1111111111111111111111111111111111111":
                prefix = "solanac_sysvar"
            elif owner == "Vote111111111111111111111111111111111111111":
                prefix = "solanac_vote"
            else:
                prefix = "solanac_acct"
            bin_path = f"{DUMP_DIR}/{prefix}_prev_{SLOT}_{pk}.bin"
            if os.path.exists(bin_path):
                with open(bin_path, "rb") as f:
                    prev_data = f.read()
            else:
                skipped += 1
                continue
        else:
            prev_data = b""
            
        prev_lth_bytes = compute_account_lt_hash_bytes(prev_lamports, prev_data, executable, owner_bytes, pk_bytes)
        prev_lth = np.frombuffer(prev_lth_bytes, dtype=np.uint16)
        
        # Verify prev prefix
        tsv_prev_prefix = acct["prev_lthash"]
        computed_prev_prefix = prev_lth_bytes[:16].hex()
        if computed_prev_prefix != tsv_prev_prefix:
            mismatches += 1
            print(f"  PREV MISMATCH #{idx}: {pk} computed={computed_prev_prefix} tsv={tsv_prev_prefix}")
        
        # Add to delta: mix_in(curr) - mix_out(prev)
        acct_delta = curr_lth.astype(np.int32) - prev_lth.astype(np.int32)
        total_delta = (total_delta.astype(np.int32) + acct_delta).astype(np.uint16)
    
    print(f"\nAccounts processed: {len(accounts)}")
    print(f"Skipped (missing data): {skipped}")
    print(f"Lt_hash prefix mismatches: {mismatches}")
    
    # Recompute final
    recomputed_final = (base.astype(np.int32) + total_delta.astype(np.int32)).astype(np.uint16)
    recomputed_cksum = lt_hash_checksum(recomputed_final)
    print(f"\nRecomputed final: {recomputed_cksum}")
    print(f"Actual final:     {lt_hash_checksum(final)}")
    print(f"Match: {recomputed_cksum == lt_hash_checksum(final)}")
    
    # Check stored delta
    stored_delta = (final.astype(np.int32) - base.astype(np.int32)).astype(np.uint16)
    
    # Compare element by element
    diff = (total_delta.astype(np.int32) - stored_delta.astype(np.int32)) & 0xFFFF
    nonzero = np.count_nonzero(diff)
    print(f"\nDelta differences: {nonzero}/1024 elements")
    
    if nonzero > 0 and nonzero <= 20:
        indices = np.where(diff != 0)[0]
        for i in indices[:20]:
            print(f"  [{i}]: computed={total_delta[i]} stored={stored_delta[i]} diff={diff[i]}")

if __name__ == "__main__":
    main()
