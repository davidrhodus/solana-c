#!/usr/bin/env bash
#
# compare-bank-frozen.sh
#
# Offline bank-hash parity helper.
#
# Usage:
#   scripts/compare-bank-frozen.sh <agave.validator.log> <solanac.validator.log>
#

set -euo pipefail

AGAVE_LOG="${1:-}"
SOLANAC_LOG="${2:-}"

if [[ -z "${AGAVE_LOG}" || -z "${SOLANAC_LOG}" ]]; then
  echo "Usage: scripts/compare-bank-frozen.sh <agave.log> <solanac.log>" >&2
  exit 2
fi
[[ -f "${AGAVE_LOG}" ]] || { echo "error: file not found: ${AGAVE_LOG}" >&2; exit 2; }
[[ -f "${SOLANAC_LOG}" ]] || { echo "error: file not found: ${SOLANAC_LOG}" >&2; exit 2; }

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT INT TERM

AGAVE_FROZEN="${tmpdir}/agave.bank_frozen.tsv"
SOLANAC_FROZEN="${tmpdir}/solanac.bank_frozen.tsv"
MISMATCHES="${tmpdir}/mismatches.txt"

extract_bank_frozen() {
  awk '
    /bank frozen:/ {
      slot = "";
      hash = "";
      sig = "";
      last = "";
      lt = "";
      for (i = 1; i <= NF; i++) {
        if ($i == "frozen:" && (i+1) <= NF) { slot = $(i+1); }
        if ($i == "hash:" && (i+1) <= NF) { hash = $(i+1); }
        if ($i == "signature_count:" && (i+1) <= NF) { sig = $(i+1); }
        if ($i == "last_blockhash:" && (i+1) <= NF) { last = $(i+1); }
        if ($i == "checksum:" && (i+1) <= NF) { lt = $(i+1); }
      }

      gsub(/[^0-9]/, "", slot);
      gsub(/[^0-9]/, "", sig);
      gsub(/[^1-9A-HJ-NP-Za-km-z]/, "", hash);
      gsub(/[^1-9A-HJ-NP-Za-km-z]/, "", last);
      gsub(/[^1-9A-HJ-NP-Za-km-z]/, "", lt);

      if (slot != "" && hash != "") {
        if (sig == "") sig = "-";
        if (last == "") last = "-";
        if (lt == "") lt = "-";
        print slot, hash, sig, last, lt;
      }
    }
  ' "$1" | sort -n -k1,1 -k2,2 | uniq
}

extract_bank_frozen "${AGAVE_LOG}" >"${AGAVE_FROZEN}" || true
extract_bank_frozen "${SOLANAC_LOG}" >"${SOLANAC_FROZEN}" || true

if [[ ! -s "${AGAVE_FROZEN}" ]]; then
  echo "error: no bank frozen hashes found in ${AGAVE_LOG}" >&2
  exit 1
fi
if [[ ! -s "${SOLANAC_FROZEN}" ]]; then
  echo "error: no bank frozen hashes found in ${SOLANAC_LOG}" >&2
  exit 1
fi

awk '
  FNR==NR {
    ag[$1, $2] = 1;
    ag_slot[$1] = 1;
    next
  }
  {
    sc[$1, $2] = 1;
    sc_slot[$1] = 1;
  }
  END {
    mism = 0;
    for (s in ag_slot) {
      if (!sc_slot[s]) continue;
      ok = 0;
      for (pair in ag) {
        split(pair, a, SUBSEP);
        if (a[1] != s) continue;
        if (sc[a[1], a[2]]) { ok = 1; break; }
      }
      if (!ok) {
        print s;
        mism++;
      }
    }
    exit(mism ? 1 : 0);
  }
' "${AGAVE_FROZEN}" "${SOLANAC_FROZEN}" >"${MISMATCHES}" || true

echo "Agave:    $(wc -l <"${AGAVE_FROZEN}" | tr -d ' ') entries"
echo "solana-c: $(wc -l <"${SOLANAC_FROZEN}" | tr -d ' ') entries"

if [[ -s "${MISMATCHES}" ]]; then
  echo ""
  echo "Mismatch detected for slots (showing up to 20):"
  head -n 20 "${MISMATCHES}"
  echo ""
  echo "Per-slot bank freeze details (Agave vs solana-c):"
  while read -r s; do
    [[ -n "$s" ]] || continue
    echo "slot $s"
    echo "  agave:"
    awk -v ss="$s" '$1==ss {printf "    hash=%s sig=%s last=%s lt=%s\n", $2, $3, $4, $5}' "${AGAVE_FROZEN}" || true
    echo "  solana-c:"
    awk -v ss="$s" '$1==ss {printf "    hash=%s sig=%s last=%s lt=%s\n", $2, $3, $4, $5}' "${SOLANAC_FROZEN}" || true
  done < <(head -n 20 "${MISMATCHES}")
  exit 1
fi

echo ""
echo "OK: solana-c bank hashes match Agave for all overlapping frozen slots."

