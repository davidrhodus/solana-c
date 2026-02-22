#!/usr/bin/env python3
"""
Find which account(s) cause lt_hash divergence between SolanaC and Agave at slot 400986229.

Strategy:
1. Load SolanaC's lt_hash_base and lt_hash_final for slot 229
2. Load per-category deltas (sysvar, vote, system, token, stake, other)
3. Try removing each category to see if we can match Agave's expected checksum
4. Then drill down into the problematic category to find specific account(s)
"""

import struct
import hashlib
import os
import sys
import csv

# pip install blake3 base58
try:
    import blake3
except ImportError:
    print("Installing blake3...")
    os.system("pip3 install blake3")
    import blake3

try:
    import base58
except ImportError:
    print("Installing base58...")
    os.system("pip3 install base58")
    import base58

DUMP_DIR = "/home/ubuntu/solana-c/agave-reptest/delta_dumps"
SLOT = 400986229
AGAVE_LT_HASH_CHECKSUM_B58 = "8zbDNYddDGxkL6Koeh4SnzSahT4aVskEQGT1y5fWPNhY"
SOLANAC_LT_HASH_CHECKSUM_B58 = "Fo8Bgg1iYTD9fQohkAM6sHat1BAcMQfgQveMsyK4166z"

def load_lt_hash(path):
    """Load a 2048-byte lt_hash file as array of 1024 uint16 values."""
    with open(path, "rb") as f:
        data = f.read()
    assert len(data) == 2048, f"Expected 2048 bytes, got {len(data)} in {path}"
    return list(struct.unpack("<1024H", data))

def lt_hash_to_bytes(lth):
    """Convert 1024 uint16 array to 2048 bytes."""
    return struct.pack("<1024H", *lth)

def lt_hash_checksum(lth):
    """Compute BLAKE3 checksum of lt_hash, return as base58 string."""
    data = lt_hash_to_bytes(lth)
    h = blake3.blake3(data).digest()
    return base58.b58encode(h).decode()

def lt_hash_add(a, b):
    """Element-wise u16 addition (wrapping)."""
    return [(a[i] + b[i]) & 0xFFFF for i in range(1024)]

def lt_hash_sub(a, b):
    """Element-wise u16 subtraction (wrapping)."""
    return [(a[i] - b[i]) & 0xFFFF for i in range(1024)]

def lt_hash_is_zero(lth):
    """Check if lt_hash is identity (all zeros)."""
    return all(v == 0 for v in lth)

def compute_account_lt_hash(lamports, data, executable, owner_bytes, pubkey_bytes):
    """Compute the 2048-byte BLAKE3-XOF lt_hash for an account."""
    if lamports == 0:
        return [0] * 1024

    buf = struct.pack("<Q", lamports) + data + struct.pack("B", 1 if executable else 0) + owner_bytes + pubkey_bytes
    h = blake3.blake3(buf)
    xof = h.digest(length=2048)
    return list(struct.unpack("<1024H", xof))

def b58_to_bytes(s):
    """Decode base58 string to 32 bytes."""
    return base58.b58decode(s)

def main():
    print(f"=== Finding divergent account(s) at slot {SLOT} ===\n")

    # Load base and final lt_hash
    base = load_lt_hash(f"{DUMP_DIR}/lt_hash_base.{SLOT}.bin")
    final = load_lt_hash(f"{DUMP_DIR}/lt_hash_final.{SLOT}.bin")

    base_cksum = lt_hash_checksum(base)
    final_cksum = lt_hash_checksum(final)
    print(f"SolanaC base  checksum: {base_cksum}")
    print(f"SolanaC final checksum: {final_cksum}")
    print(f"Expected SolanaC final: {SOLANAC_LT_HASH_CHECKSUM_B58}")
    print(f"Expected Agave  final:  {AGAVE_LT_HASH_CHECKSUM_B58}")
    print(f"SolanaC final matches expected: {final_cksum == SOLANAC_LT_HASH_CHECKSUM_B58}")
    print()

    # Total delta = final - base
    total_delta = lt_hash_sub(final, base)

    # Load per-category deltas
    categories = ["sysvar", "vote", "system", "token", "stake", "other"]
    cat_deltas = {}
    for cat in categories:
        path = f"{DUMP_DIR}/lt_hash_{cat}_delta.{SLOT}.bin"
        if os.path.exists(path):
            cat_deltas[cat] = load_lt_hash(path)
            is_zero = lt_hash_is_zero(cat_deltas[cat])
            print(f"  {cat:10s} delta loaded (zero={is_zero})")
        else:
            print(f"  {cat:10s} delta NOT FOUND")
            cat_deltas[cat] = [0] * 1024

    # Also load the nonsysvar delta
    nonsysvar_path = f"{DUMP_DIR}/lt_hash_nonsysvar_delta.{SLOT}.bin"
    if os.path.exists(nonsysvar_path):
        nonsysvar_delta = load_lt_hash(nonsysvar_path)
        print(f"  {'nonsysvar':10s} delta loaded")

    print()

    # Verify: sum of categories should equal total delta
    recomputed = [0] * 1024
    for cat in categories:
        recomputed = lt_hash_add(recomputed, cat_deltas[cat])
    recomp_matches = (recomputed == total_delta)
    print(f"Sum of categories == total delta: {recomp_matches}")
    if not recomp_matches:
        diff_count = sum(1 for i in range(1024) if recomputed[i] != total_delta[i])
        print(f"  Differences in {diff_count}/1024 elements")
    print()

    # Try removing each category to see which one(s) cause the divergence
    print("=== Testing category removal ===")
    for cat in categories:
        if lt_hash_is_zero(cat_deltas[cat]):
            continue
        adjusted = lt_hash_sub(final, cat_deltas[cat])
        cksum = lt_hash_checksum(adjusted)
        match = "MATCH!" if cksum == AGAVE_LT_HASH_CHECKSUM_B58 else ""
        print(f"  Remove {cat:10s}: {cksum[:20]}... {match}")

    # Try combinations of 2 categories
    print("\n=== Testing pairs of category removal ===")
    for i in range(len(categories)):
        for j in range(i+1, len(categories)):
            c1, c2 = categories[i], categories[j]
            if lt_hash_is_zero(cat_deltas[c1]) and lt_hash_is_zero(cat_deltas[c2]):
                continue
            adjusted = lt_hash_sub(lt_hash_sub(final, cat_deltas[c1]), cat_deltas[c2])
            cksum = lt_hash_checksum(adjusted)
            match = "MATCH!" if cksum == AGAVE_LT_HASH_CHECKSUM_B58 else ""
            if match:
                print(f"  Remove {c1}+{c2}: {cksum[:20]}... {match}")

    # Now let's do the per-account analysis
    # Load TSV
    tsv_path = f"{DUMP_DIR}/delta_accounts.{SLOT}.tsv"
    accounts = []
    with open(tsv_path, "r") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            accounts.append(row)

    print(f"\n=== Per-account analysis: {len(accounts)} accounts ===\n")

    # For each account, we need to compute the full 2048-byte curr and prev lt_hash
    # Then compute the account's delta (mix_in(curr) - mix_out(prev) = curr_hash - prev_hash)
    # Then try removing that delta from the total

    # Categorize accounts
    cat_accounts = {cat: [] for cat in categories}
    for acct in accounts:
        owner = acct["owner"]
        if owner == "Sysvar1111111111111111111111111111111111111":
            cat_accounts["sysvar"].append(acct)
        elif owner == "Vote111111111111111111111111111111111111111":
            cat_accounts["vote"].append(acct)
        elif owner == "11111111111111111111111111111111":
            cat_accounts["system"].append(acct)
        elif owner == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA":
            cat_accounts["token"].append(acct)
        elif owner == "Stake11111111111111111111111111111111111111":
            cat_accounts["stake"].append(acct)
        else:
            cat_accounts["other"].append(acct)

    for cat in categories:
        print(f"  {cat:10s}: {len(cat_accounts[cat])} accounts")

    # First, let's identify the problematic category by checking which single-category
    # removal gets us closest to Agave's expected checksum
    # Then do per-account search within that category

    # Compute per-account lt_hash contributions for the problematic categories
    print("\n=== Computing per-account lt_hash contributions ===")

    def get_account_lthash(acct, which="curr"):
        """Compute full 2048-byte lt_hash for an account state."""
        if which == "curr":
            lamports = int(acct["curr_lamports"])
            data_len = int(acct["curr_data_len"])
        else:
            lamports = int(acct["prev_lamports"])
            data_len = int(acct["prev_data_len"])

        if lamports == 0:
            return [0] * 1024

        pubkey = acct["pubkey"]
        owner = acct["owner"]
        executable = int(acct["executable"])

        pubkey_bytes = b58_to_bytes(pubkey)
        owner_bytes = b58_to_bytes(owner)

        # Load binary data if data_len > 0
        if data_len > 0:
            # Determine file prefix
            if owner == "Sysvar1111111111111111111111111111111111111":
                prefix = "solanac_sysvar"
            elif owner == "Vote111111111111111111111111111111111111111":
                prefix = "solanac_vote"
            else:
                prefix = "solanac_acct"

            if which == "curr":
                bin_path = f"{DUMP_DIR}/{prefix}_{SLOT}_{pubkey}.bin"
            else:
                bin_path = f"{DUMP_DIR}/{prefix}_prev_{SLOT}_{pubkey}.bin"

            if os.path.exists(bin_path):
                with open(bin_path, "rb") as f:
                    data = f.read()
                if len(data) != data_len:
                    print(f"  WARNING: {pubkey} {which} data_len mismatch: file={len(data)} tsv={data_len}")
                    # Use file data anyway
            else:
                # No binary dump - we can't compute exact lt_hash
                # Return None to indicate we can't compute it
                return None
        else:
            data = b""

        return compute_account_lt_hash(lamports, data, executable, owner_bytes, pubkey_bytes)

    # First, try all sysvar accounts (only 4, quick to check)
    print("\n--- Sysvar accounts ---")
    for acct in cat_accounts["sysvar"]:
        pk = acct["pubkey"]
        curr_lth = get_account_lthash(acct, "curr")
        prev_lth = get_account_lthash(acct, "prev")
        if curr_lth is None or prev_lth is None:
            print(f"  {pk}: SKIP (missing data)")
            continue
        # Account delta = curr_lth - prev_lth
        acct_delta = lt_hash_sub(curr_lth, prev_lth)
        # Remove this account's delta from total
        adjusted = lt_hash_sub(final, acct_delta)
        cksum = lt_hash_checksum(adjusted)
        match = "MATCH!" if cksum == AGAVE_LT_HASH_CHECKSUM_B58 else ""
        # Also verify first 16 bytes match TSV
        curr_prefix = lt_hash_to_bytes(curr_lth)[:16].hex()
        tsv_prefix = acct["curr_lthash"]
        pfx_match = "OK" if curr_prefix == tsv_prefix else "MISMATCH"
        print(f"  {pk}: lthash_prefix={pfx_match} remove→{cksum[:20]}... {match}")

    # Now try all vote accounts - this is larger (751) so may take a moment
    print(f"\n--- Checking all {len(accounts)} accounts (may take a minute) ---")
    matches_found = []
    errors = []
    computed_total_delta = [0] * 1024

    for idx, acct in enumerate(accounts):
        pk = acct["pubkey"]
        curr_lth = get_account_lthash(acct, "curr")
        prev_lth = get_account_lthash(acct, "prev")

        if curr_lth is None:
            errors.append((pk, "missing curr data"))
            continue
        if prev_lth is None:
            errors.append((pk, "missing prev data"))
            continue

        acct_delta = lt_hash_sub(curr_lth, prev_lth)
        computed_total_delta = lt_hash_add(computed_total_delta, acct_delta)

        # Remove this account's delta from the final hash
        adjusted = lt_hash_sub(final, acct_delta)
        cksum = lt_hash_checksum(adjusted)
        if cksum == AGAVE_LT_HASH_CHECKSUM_B58:
            matches_found.append(pk)
            print(f"  *** MATCH: removing {pk} gives Agave's expected checksum! ***")

        if (idx + 1) % 500 == 0:
            print(f"  ... processed {idx+1}/{len(accounts)}")

    print(f"\n  Processed: {len(accounts)} accounts")
    print(f"  Errors (missing data): {len(errors)}")
    print(f"  Matches found: {len(matches_found)}")

    if errors:
        print(f"\n  First 10 errors:")
        for pk, err in errors[:10]:
            print(f"    {pk}: {err}")

    if matches_found:
        print(f"\n  *** DIVERGENT ACCOUNTS: ***")
        for pk in matches_found:
            acct = [a for a in accounts if a["pubkey"] == pk][0]
            print(f"    {pk}")
            print(f"      owner: {acct['owner']}")
            print(f"      curr_lamports: {acct['curr_lamports']}")
            print(f"      prev_lamports: {acct['prev_lamports']}")
            print(f"      curr_data_len: {acct['curr_data_len']}")
            print(f"      prev_data_len: {acct['prev_data_len']}")
            print(f"      type: {acct['type']}")
            print(f"      executable: {acct['executable']}")
    else:
        print("\n  No single-account removal matches Agave's checksum.")
        print("  Trying: is the delta difference small?")

        # Compute what the SolanaC delta is
        computed_cksum = lt_hash_checksum(lt_hash_add(base, computed_total_delta))
        print(f"  Recomputed final from per-acct deltas: {computed_cksum}")
        print(f"  Original final:                        {final_cksum}")
        print(f"  Match: {computed_cksum == final_cksum}")

        # Try: maybe Agave has EXTRA accounts (e.g. eager rent sweep)
        # The difference = Agave_final - SolanaC_final
        # We don't have Agave_final as raw vector, but we can check
        # if SolanaC has accounts that should NOT be in the delta

        # Check for accounts with equal curr and prev (should have been skipped)
        print("\n  Checking for accounts where curr == prev (should be skipped):")
        unchanged = []
        for acct in accounts:
            if (acct["curr_lamports"] == acct["prev_lamports"] and
                acct["curr_data_len"] == acct["prev_data_len"] and
                acct["data_hash"] == acct["prev_data_hash"]):
                pk = acct["pubkey"]
                unchanged.append(pk)
                # But also need to check executable... it's in curr only

        print(f"  Accounts with matching metadata+data_hash: {len(unchanged)}")
        if unchanged:
            for pk in unchanged[:10]:
                acct = [a for a in accounts if a["pubkey"] == pk][0]
                print(f"    {pk} (owner={acct['owner'][:20]}... lam={acct['curr_lamports']})")

        # Try removing all accounts that appear unchanged
        if unchanged:
            adjusted = list(final)
            for pk in unchanged:
                acct = [a for a in accounts if a["pubkey"] == pk][0]
                curr_lth = get_account_lthash(acct, "curr")
                prev_lth = get_account_lthash(acct, "prev")
                if curr_lth and prev_lth:
                    acct_delta = lt_hash_sub(curr_lth, prev_lth)
                    adjusted = lt_hash_sub(adjusted, acct_delta)
            cksum = lt_hash_checksum(adjusted)
            match = "MATCH!" if cksum == AGAVE_LT_HASH_CHECKSUM_B58 else ""
            print(f"\n  Remove all {len(unchanged)} unchanged: {cksum[:20]}... {match}")

        # Try pairs of account removals for accounts with smallest data
        print("\n  Computing delta difference (SolanaC_delta - recomputed_delta):")
        diff = lt_hash_sub(total_delta, computed_total_delta)
        diff_nonzero = sum(1 for v in diff if v != 0)
        print(f"  Non-zero elements in difference: {diff_nonzero}/1024")

if __name__ == "__main__":
    main()
