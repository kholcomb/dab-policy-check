#!/usr/bin/env bash
# Smoke test for scripts/conftest_report.py: triage, severity threshold,
# emitters, and waiver flag behavior.
#
# Generates ephemeral exception YAMLs with current dates so the fixtures
# don't go stale. Static fixtures (good.json, bad.json) are reused.

set -uo pipefail
cd "$(dirname "$0")"

POLICY_DIR="$(cd ../policy && pwd)"
CATALOG="$POLICY_DIR/dab.catalog.yaml"
REPORTER="$(cd ../scripts && pwd)/conftest_report.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# bad.json ships with placeholders for credential-shaped test patterns so the
# repo doesn't trip GitHub push protection. Substitute the real patterns into
# a tmp copy at runtime so the reporter's P12 rule still fires.
sed -e 's/PLACEHOLDER_DAPI_TOKEN/dapi0123456789abcdef0123456789abcdef/' \
    -e 's/PLACEHOLDER_AKIA_KEY/AKIAIOSFODNN7EXAMPLE/' \
    bad.json > "$TMPDIR/bad.json"
BAD="$TMPDIR/bad.json"

# UTC dates to match reporter's pipeline_today().
TODAY=$(python3 -c "from datetime import datetime, timezone; print(datetime.now(timezone.utc).date().isoformat())")
PLUS_30=$(python3 -c "from datetime import datetime, timezone, timedelta; print((datetime.now(timezone.utc).date() + timedelta(days=30)).isoformat())")
MINUS_30=$(python3 -c "from datetime import datetime, timezone, timedelta; print((datetime.now(timezone.utc).date() - timedelta(days=30)).isoformat())")
MINUS_60=$(python3 -c "from datetime import datetime, timezone, timedelta; print((datetime.now(timezone.utc).date() - timedelta(days=60)).isoformat())")

assert_eq() {
  if [ "$1" != "$2" ]; then
    echo "FAIL: $3 (expected $1, got $2)" >&2
    exit 1
  fi
}

assert_ge() {
  if [ "$1" -lt "$2" ]; then
    echo "FAIL: $3 (expected >= $2, got $1)" >&2
    exit 1
  fi
}

run_reporter() {
  python3 "$REPORTER" \
    --policy "$POLICY_DIR" --catalog "$CATALOG" \
    --json "$TMPDIR/report.json" "$@" >/dev/null 2>&1
  echo $?
}

count() {
  python3 -c "import json; d=json.load(open('$TMPDIR/report.json')); print(d['totals']['$1'])"
}

count_marker() {
  python3 -c "import json; d=json.load(open('$TMPDIR/report.json')); print(sum(1 for f in d['active'] if '$1' in f['body']))"
}

# ---------- T1: good.json, no exceptions ----------
echo "== T1: good.json, no exceptions"
exit_code=$(run_reporter --bundle good.json --fail-on high)
assert_eq 0 "$exit_code" "T1 exit code"

# ---------- T2: bad.json, no exceptions ----------
echo "== T2: bad.json, no exceptions"
exit_code=$(run_reporter --bundle "$BAD" --fail-on high)
assert_eq 1 "$exit_code" "T2 exit code"
assert_ge "$(count active)" 25 "T2 active count"
assert_eq 0 "$(count waived)" "T2 waived count"

# ---------- T3: bad.json + active P11 waiver ----------
cat > "$TMPDIR/active.yaml" <<EOF
- rule_id: P11
  resource: "resources.jobs.bad_job.tasks[*].libraries[*].pypi"
  reason: legacy package, migration tracked in DATA-1234
  approver: alice@example.com
  approved: "$TODAY"
  expires: "$PLUS_30"
EOF
echo "== T3: bad.json + active waiver (P11 PyPI x2)"
exit_code=$(run_reporter --bundle "$BAD" --exceptions "$TMPDIR/active.yaml" --fail-on high)
assert_eq 1 "$exit_code" "T3 exit code (other Highs/Criticals remain)"
assert_eq 2 "$(count waived)" "T3 waived count"

# ---------- T4: bad.json + expired waiver ----------
cat > "$TMPDIR/expired.yaml" <<EOF
- rule_id: P11
  resource: "resources.jobs.bad_job.tasks[*].libraries[*].pypi"
  reason: same waiver, lapsed
  approver: alice@example.com
  approved: "$MINUS_60"
  expires: "$MINUS_30"
EOF
echo "== T4: bad.json + expired waiver (must be promoted to active)"
exit_code=$(run_reporter --bundle "$BAD" --exceptions "$TMPDIR/expired.yaml" --fail-on high)
assert_eq 1 "$exit_code" "T4 exit code"
assert_eq 0 "$(count waived)" "T4 waived count (expired -> active)"
assert_eq 2 "$(count_marker EXPIRED-WAIVER)" "T4 EXPIRED-WAIVER markers"

# ---------- T5: --strict-waivers with unused exception ----------
cat > "$TMPDIR/unused.yaml" <<EOF
- rule_id: P11
  resource: "resources.jobs.does_not_exist.tasks[*].libraries[*].pypi"
  reason: stale, resource was renamed
  approver: alice@example.com
  approved: "$TODAY"
  expires: "$PLUS_30"
EOF
echo "== T5: bad.json + unused waiver + --strict-waivers"
exit_code=$(run_reporter --bundle "$BAD" --exceptions "$TMPDIR/unused.yaml" --strict-waivers --fail-on none)
assert_eq 1 "$exit_code" "T5 exit code (--strict-waivers)"
assert_eq 1 "$(count unused_exceptions)" "T5 unused count"

# ---------- T6: --no-waive-critical ----------
cat > "$TMPDIR/critical.yaml" <<EOF
- rule_id: P10
  resource: "*"
  reason: trying to waive a Critical
  approver: alice@example.com
  approved: "$TODAY"
  expires: "$PLUS_30"
EOF
echo "== T6: bad.json + Critical waiver + --no-waive-critical"
exit_code=$(run_reporter --bundle "$BAD" --exceptions "$TMPDIR/critical.yaml" --no-waive-critical --fail-on high)
assert_eq 1 "$exit_code" "T6 exit code"
rejected=$(count_marker WAIVER-REJECTED)
assert_ge "$rejected" 1 "T6 WAIVER-REJECTED markers"

# ---------- T7: JUnit emitter shape ----------
echo "== T7: JUnit emitter (failures + skipped)"
python3 "$REPORTER" --policy "$POLICY_DIR" --catalog "$CATALOG" \
  --bundle "$BAD" --exceptions "$TMPDIR/active.yaml" \
  --junit "$TMPDIR/r.xml" --fail-on none >/dev/null
failures=$(grep -c '<failure ' "$TMPDIR/r.xml")
skipped=$(grep -c '<skipped ' "$TMPDIR/r.xml")
assert_ge "$failures" 25 "T7 <failure> count"
assert_eq 2 "$skipped" "T7 <skipped> count"

# ---------- T8: SARIF suppressions on waived ----------
echo "== T8: SARIF suppressions on waived findings"
python3 "$REPORTER" --policy "$POLICY_DIR" --catalog "$CATALOG" \
  --bundle "$BAD" --exceptions "$TMPDIR/active.yaml" \
  --sarif "$TMPDIR/r.sarif" --fail-on none >/dev/null
suppressed=$(python3 -c "import json; d=json.load(open('$TMPDIR/r.sarif')); print(sum(1 for r in d['runs'][0]['results'] if 'suppressions' in r))")
assert_eq 2 "$suppressed" "T8 SARIF suppressed count"

# ---------- T9: Markdown 'Waived' section ----------
echo "== T9: Markdown 'Waived' section present"
python3 "$REPORTER" --policy "$POLICY_DIR" --catalog "$CATALOG" \
  --bundle "$BAD" --exceptions "$TMPDIR/active.yaml" \
  --markdown "$TMPDIR/r.md" --fail-on none >/dev/null
grep -q '## Waived' "$TMPDIR/r.md" || { echo "FAIL: T9 missing Waived section" >&2; exit 1; }

echo
echo "All reporter tests PASS."
