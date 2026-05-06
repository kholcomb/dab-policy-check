#!/usr/bin/env bash
# Smoke test for DAB/policy/dab.rego.
#   - good.json: every rule should pass (zero deny messages).
#   - bad.json:  every implemented P-rule should fire at least once.
#
# Requires `conftest` on PATH. From the repo root or this directory:
#   ./test_policy.sh

set -uo pipefail
cd "$(dirname "$0")"
POLICY_DIR="$(cd ../policy && pwd)"

EXPECTED_RULES=(P2 P3 P4 P5 P6 P7 P8 P9 P10 P11 P12 P13 P15 P16)

# ---------- good.json ----------
echo "==> good.json (expect 0 denies)"
GOOD_OUTPUT=$(conftest test --policy "$POLICY_DIR" --all-namespaces good.json 2>&1)
GOOD_STATUS=$?
echo "$GOOD_OUTPUT"
if [ $GOOD_STATUS -ne 0 ]; then
  echo "FAIL: good.json triggered deny rules" >&2
  exit 1
fi
echo "  PASS"
echo

# ---------- bad.json ----------
echo "==> bad.json (expect every P-rule to fire)"
BAD_OUTPUT=$(conftest test --policy "$POLICY_DIR" --all-namespaces bad.json 2>&1 || true)
echo "$BAD_OUTPUT"
echo

MISSING=()
for rule in "${EXPECTED_RULES[@]}"; do
  if ! grep -qE "\[${rule}/" <<<"$BAD_OUTPUT"; then
    MISSING+=("$rule")
  fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "FAIL: bad.json did not trigger expected rules: ${MISSING[*]}" >&2
  exit 1
fi
echo "  PASS: every expected rule fired against bad.json"
echo
echo "Fixture pack OK."
