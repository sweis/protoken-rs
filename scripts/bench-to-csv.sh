#!/usr/bin/env bash
# Run criterion benchmarks and append results as a CSV row to PERFORMANCE.md.
#
# Usage:
#   ./scripts/bench-to-csv.sh              # run benchmarks, append to PERFORMANCE.md
#   ./scripts/bench-to-csv.sh --dry-run    # print CSV row to stdout only
#
# Each run appends one row with columns:
#   date, git_rev, cpu, os,
#   hmac_sign_ns, hmac_verify_ns,
#   ed25519_sign_ns, ed25519_verify_ns,
#   mldsa44_sign_ns, mldsa44_verify_ns

set -euo pipefail
cd "$(dirname "$0")/.."

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

# Collect platform metadata
DATE=$(date -u +"%Y-%m-%d")
GIT_REV=$(git rev-parse --short HEAD)
CPU=$(lscpu 2>/dev/null | grep "Model name" | sed 's/.*:\s*//' || uname -m)
OS=$(uname -s)

# Run criterion in baseline mode, capturing output
echo "Running benchmarks..." >&2
BENCH_OUTPUT=$(cargo bench 2>&1)

# Parse median times from criterion output.
# Criterion prints: "bench_name  time:   [352.61 ns 355.82 ns 359.57 ns]"
# We extract the median (second value+unit pair) and normalize to nanoseconds.
parse_time() {
  local name="$1"
  local line
  line=$(echo "$BENCH_OUTPUT" | grep "^${name} " | grep "time:")
  if [[ -z "$line" ]]; then
    echo "ERROR: could not find benchmark '$name' in output" >&2
    echo "0"
    return
  fi
  # Extract content between brackets, split into 6 tokens: val1 unit1 val2 unit2 val3 unit3
  local bracket_content
  bracket_content=$(echo "$line" | sed 's/.*\[//;s/\]//')
  # Median is the 3rd and 4th tokens (second value+unit pair)
  local median unit
  median=$(echo "$bracket_content" | awk '{print $3}')
  unit=$(echo "$bracket_content" | awk '{print $4}')
  # Normalize to nanoseconds
  case "$unit" in
    ns) echo "$median" ;;
    µs|us) echo "$median * 1000" | bc ;;
    ms) echo "$median * 1000000" | bc ;;
    s)  echo "$median * 1000000000" | bc ;;
    *) echo "WARN: unknown unit '$unit' for $name" >&2; echo "$median" ;;
  esac
}

HMAC_SIGN=$(parse_time "hmac_sign")
HMAC_VERIFY=$(parse_time "hmac_verify")
ED25519_SIGN=$(parse_time "ed25519_sign")
ED25519_VERIFY=$(parse_time "ed25519_verify")
MLDSA44_SIGN=$(parse_time "mldsa44_sign")
MLDSA44_VERIFY=$(parse_time "mldsa44_verify")

ROW="$DATE,$GIT_REV,$CPU,$OS,$HMAC_SIGN,$HMAC_VERIFY,$ED25519_SIGN,$ED25519_VERIFY,$MLDSA44_SIGN,$MLDSA44_VERIFY"

if $DRY_RUN; then
  echo "$ROW"
  exit 0
fi

# Append to the CSV table in PERFORMANCE.md
if [[ ! -f PERFORMANCE.md ]]; then
  echo "ERROR: PERFORMANCE.md not found. Create it first." >&2
  exit 1
fi

# Check if the CSV section already has this row (idempotency by date+rev)
if grep -q "^$DATE,$GIT_REV," PERFORMANCE.md 2>/dev/null; then
  echo "Row for $DATE/$GIT_REV already exists in PERFORMANCE.md, skipping." >&2
  exit 0
fi

echo "$ROW" >> PERFORMANCE.md
echo "Appended benchmark row to PERFORMANCE.md" >&2
echo "$ROW"
