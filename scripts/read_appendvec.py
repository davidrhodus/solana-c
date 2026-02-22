#!/usr/bin/env python3
"""Read specific accounts from Agave AppendVec storage files."""

import struct
import sys
import os
import hashlib
import base58

# AppendVec per-account layout:
# Offset  Size  Field
# 0       8     write_version (u64, obsolete)
# 8       8     data_len (u64)
# 16      32    pubkey
# 48      8     lamports (u64)
# 56      8     rent_epoch (u64)
# 64      32    owner pubkey
# 96      1     executable (bool)
# 97      7     padding
# 104     32    account_hash (obsolete)
# 136     N     data (N = data_len)
# 136+N   pad   alignment padding to 8 bytes

HEADER_SIZE = 136

def align8(n):
    return (n + 7) & ~7

def read_accounts(filepath, target_pubkeys=None):
    """Read accounts from an AppendVec file.

    Args:
        filepath: Path to the AppendVec file
        target_pubkeys: Optional set of pubkey bytes to filter for

    Returns:
        List of (pubkey_bytes, lamports, rent_epoch, owner_bytes, executable, data) tuples
    """
    results = []
    try:
        filesize = os.path.getsize(filepath)
        if filesize < HEADER_SIZE:
            return results

        with open(filepath, 'rb') as f:
            offset = 0
            while offset + HEADER_SIZE <= filesize:
                f.seek(offset)
                header = f.read(HEADER_SIZE)
                if len(header) < HEADER_SIZE:
                    break

                write_version = struct.unpack_from('<Q', header, 0)[0]
                data_len = struct.unpack_from('<Q', header, 8)[0]
                pubkey = header[16:48]
                lamports = struct.unpack_from('<Q', header, 48)[0]
                rent_epoch = struct.unpack_from('<Q', header, 56)[0]
                owner = header[64:96]
                executable = header[96] != 0

                # Sanity check
                if data_len > 10_000_000 or offset + HEADER_SIZE + data_len > filesize:
                    break

                # Read data
                data = f.read(data_len) if data_len > 0 else b''
                if len(data) < data_len:
                    break

                if target_pubkeys is None or pubkey in target_pubkeys:
                    results.append({
                        'pubkey': pubkey,
                        'lamports': lamports,
                        'rent_epoch': rent_epoch,
                        'owner': owner,
                        'executable': executable,
                        'data': data,
                        'data_len': data_len,
                        'write_version': write_version,
                    })

                # Advance to next account
                entry_size = align8(HEADER_SIZE + data_len)
                offset += entry_size

    except Exception as e:
        pass  # Skip unreadable files

    return results

def data_hash(data):
    """Compute SHA256 of data, return first 8 bytes as hex."""
    if not data:
        return "0000000000000000"
    h = hashlib.sha256(data).digest()
    return h[:8].hex()

def pubkey_to_base58(pubkey_bytes):
    """Convert 32-byte pubkey to base58 string."""
    return base58.b58encode(pubkey_bytes).decode()

def main():
    if len(sys.argv) < 3:
        print("Usage: read_appendvec.py <accounts_dir> <pubkey1> [pubkey2 ...]")
        print("  Or: read_appendvec.py <accounts_dir> --from-tsv <delta_dump.tsv>")
        sys.exit(1)

    accounts_dir = sys.argv[1]

    # Parse target pubkeys
    target_pubkeys = set()
    if sys.argv[2] == '--from-tsv':
        tsv_file = sys.argv[3]
        import csv
        with open(tsv_file) as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                pk_bytes = base58.b58decode(row['pubkey'])
                target_pubkeys.add(pk_bytes)
        print(f"Loaded {len(target_pubkeys)} target pubkeys from {tsv_file}")
    else:
        for pk_str in sys.argv[2:]:
            pk_bytes = base58.b58decode(pk_str)
            target_pubkeys.add(pk_bytes)

    # Scan AppendVec files
    found = {}  # pubkey -> account (keep latest write_version)
    files = os.listdir(accounts_dir)
    total = len(files)

    for idx, filename in enumerate(files):
        filepath = os.path.join(accounts_dir, filename)
        if not os.path.isfile(filepath):
            continue

        accounts = read_accounts(filepath, target_pubkeys)
        for acc in accounts:
            pk = acc['pubkey']
            # Keep account with highest write_version
            if pk not in found or acc['write_version'] > found[pk]['write_version']:
                found[pk] = acc

        if (idx + 1) % 10000 == 0:
            print(f"Scanned {idx+1}/{total} files, found {len(found)} accounts...",
                  file=sys.stderr)

    # Output results
    print("pubkey\tlamports\tdata_len\towner\texecutable\tdata_hash\twrite_version")
    for pk_bytes in sorted(found.keys()):
        acc = found[pk_bytes]
        print(f"{pubkey_to_base58(acc['pubkey'])}\t{acc['lamports']}\t{acc['data_len']}\t"
              f"{pubkey_to_base58(acc['owner'])}\t{int(acc['executable'])}\t"
              f"{data_hash(acc['data'])}\t{acc['write_version']}")

    print(f"\nFound {len(found)}/{len(target_pubkeys)} target accounts", file=sys.stderr)

if __name__ == '__main__':
    main()
