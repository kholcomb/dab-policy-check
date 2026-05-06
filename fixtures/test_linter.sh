#!/usr/bin/env bash
# Smoke test for scripts/validate_exceptions.py: lint subcommand (schema +
# expiry + optional CODEOWNERS) and notify subcommand (tier bucketing).
#
# Static fixture: exceptions/lint_bad.yaml (intentionally malformed). All
# good cases are generated inline with current dates so they don't go stale.

set -uo pipefail
cd "$(dirname "$0")"

LINTER="$(cd ../scripts && pwd)/validate_exceptions.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

TODAY=$(python3 -c "from datetime import datetime, timezone; print(datetime.now(timezone.utc).date().isoformat())")
PLUS_5=$(python3 -c "from datetime import datetime, timezone, timedelta; print((datetime.now(timezone.utc).date() + timedelta(days=5)).isoformat())")
PLUS_30=$(python3 -c "from datetime import datetime, timezone, timedelta; print((datetime.now(timezone.utc).date() + timedelta(days=30)).isoformat())")

assert_exit() {
  local expected=$1
  shift
  "$@" >/dev/null 2>&1
  local got=$?
  if [ "$got" != "$expected" ]; then
    echo "FAIL: $* (expected exit $expected, got $got)" >&2
    exit 1
  fi
}

# ---------- LINT ----------

# T1: empty list passes
echo "[]" > "$TMPDIR/empty.yaml"
echo "== L1: lint empty list"
assert_exit 0 python3 "$LINTER" lint "$TMPDIR/empty.yaml"

# T2: well-formed entry passes
cat > "$TMPDIR/good.yaml" <<EOF
- rule_id: P11
  resource: "*"
  reason: justified pin gap, tracked in DATA-1234
  approver: alice@example.com
  approved: "$TODAY"
  expires: "$PLUS_30"
EOF
echo "== L2: lint good file"
assert_exit 0 python3 "$LINTER" lint "$TMPDIR/good.yaml"

# T3: static bad fixture fails
echo "== L3: lint static lint_bad.yaml"
assert_exit 1 python3 "$LINTER" lint exceptions/lint_bad.yaml

# T4: --codeowners with eligible approver passes
echo "== L4: --codeowners eligible approver"
assert_exit 0 python3 "$LINTER" lint "$TMPDIR/good.yaml" \
  --codeowners codeowners_sample

# T5: --codeowners with ineligible approver fails
sed 's/alice@example.com/eve@example.com/' "$TMPDIR/good.yaml" > "$TMPDIR/eve.yaml"
echo "== L5: --codeowners ineligible approver"
assert_exit 1 python3 "$LINTER" lint "$TMPDIR/eve.yaml" \
  --codeowners codeowners_sample

# T6: --codeowners path missing -> hard fail (exit 2)
echo "== L6: --codeowners missing path (must hard fail)"
assert_exit 2 python3 "$LINTER" lint "$TMPDIR/good.yaml" \
  --codeowners "$TMPDIR/no_such_file"

# T7: max-future-days enforcement
PLUS_120=$(python3 -c "from datetime import datetime, timezone, timedelta; print((datetime.now(timezone.utc).date() + timedelta(days=120)).isoformat())")
cat > "$TMPDIR/far.yaml" <<EOF
- rule_id: P11
  resource: "*"
  reason: too far out
  approver: alice@example.com
  approved: "$TODAY"
  expires: "$PLUS_120"
EOF
echo "== L7: max-future-days rejects 120-day expiry"
assert_exit 1 python3 "$LINTER" lint "$TMPDIR/far.yaml" --max-future-days 90

# ---------- NOTIFY ----------

# T8: notify on empty file (no tiers populated)
echo "== N1: notify empty file"
assert_exit 0 python3 "$LINTER" notify "$TMPDIR/empty.yaml" \
  --warn-days 7,14,30 --channel stdout

# T9: notify produces a digest containing the expected tier
cat > "$TMPDIR/imminent.yaml" <<EOF
- rule_id: P11
  resource: "*"
  reason: imminent expiry
  approver: alice@example.com
  approved: "$TODAY"
  expires: "$PLUS_5"
EOF
echo "== N2: notify with imminent waiver shows <=7d tier"
output=$(python3 "$LINTER" notify "$TMPDIR/imminent.yaml" \
  --warn-days 7,14,30 --channel stdout)
echo "$output" | grep -q '<=7d' || {
  echo "FAIL: N2 expected '<=7d' tier in output" >&2
  echo "$output"
  exit 1
}

# T10: notify with healthy waiver (>30d) shows nothing
cat > "$TMPDIR/healthy.yaml" <<EOF
- rule_id: P11
  resource: "*"
  reason: still well within window
  approver: alice@example.com
  approved: "$TODAY"
  expires: "$PLUS_30"
EOF
echo "== N3: notify with healthy waiver excludes it from digest"
output=$(python3 "$LINTER" notify "$TMPDIR/healthy.yaml" \
  --warn-days 7,14 --channel stdout)
echo "$output" | grep -q "No exceptions expiring" || {
  echo "FAIL: N3 expected 'No exceptions expiring' message" >&2
  echo "$output"
  exit 1
}

echo
echo "All linter tests PASS."
