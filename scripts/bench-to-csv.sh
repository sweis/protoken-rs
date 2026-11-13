#!/usr/bin/env bash
# Run the criterion benchmarks and append one CSV row per benchmark to
# PERFORMANCE.md: date,git_rev,cpu,os,algorithm,operation,median_ns
#
# Usage: ./scripts/bench-to-csv.sh [--dry-run]    (requires jq)

set -euo pipefail
cd "$(dirname "$0")/.."

run="$(date -u +%F),$(git rev-parse --short HEAD)"
cpu=$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | tr -d , || true)

if [[ "${1:-}" != "--dry-run" ]] && grep -q "^$run," PERFORMANCE.md; then
  echo "PERFORMANCE.md already has rows for $run" >&2
  exit 0
fi

# A fresh directory keeps stale results out and saved baselines untouched.
CRITERION_HOME=$(mktemp -d)
export CRITERION_HOME
trap 'rm -rf "$CRITERION_HOME"' EXIT
cargo bench >&2

rows=$(cd "$CRITERION_HOME" && for estimates in */*/new/estimates.json; do
  IFS=/ read -r algorithm operation _ <<<"$estimates"
  median=$(jq '.median.point_estimate | round' "$estimates")
  echo "$run,${cpu:-$(uname -m)},$(uname -s),$algorithm,$operation,$median"
done)

echo "$rows"
if [[ "${1:-}" != "--dry-run" ]]; then
  echo "$rows" >>PERFORMANCE.md
fi
