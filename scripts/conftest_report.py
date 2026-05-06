#!/usr/bin/env python3
"""
conftest_report.py — Rich pre-deploy policy reporting for Databricks Asset Bundles.

Runs `conftest test` against a resolved bundle JSON, joins each finding with a
YAML rule catalog (rule_id -> {title, severity, why, fix, references}), applies
optional time-bounded exceptions from a waiver file, and emits Markdown,
JUnit, JSON, and SARIF reports.

Triage when --exceptions is supplied:
  - matching, unexpired exception   -> "waived"  (reported, does not fail)
  - matching, expired exception     -> "active"  with [EXPIRED-WAIVER] marker
  - no matching exception           -> "active"

Exit codes:
  - 0 if no active finding meets/exceeds --fail-on
  - 1 if any active finding does, OR if --strict-waivers is set and the
    exception file contains entries that did not match any finding
  - 2 on configuration errors (catalog mismatch, malformed waiver, etc.)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from pathlib import Path

import yaml


SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
SEVERITY_LABEL = {
    "Critical": "[CRITICAL]",
    "High":     "[HIGH]",
    "Medium":   "[MEDIUM]",
    "Low":      "[LOW]",
}

SEVERITY_TO_SARIF_LEVEL = {
    "Critical": "error",
    "High":     "error",
    "Medium":   "warning",
    "Low":      "note",
}

SEVERITY_TO_SECURITY_SEVERITY = {
    "Critical": "9.5",
    "High":     "8.0",
    "Medium":   "5.0",
    "Low":      "2.0",
}

MSG_RE = re.compile(
    r"^\[(?P<id>P\d+)/(?P<sev>\w+)\]\s*"
    r"(?P<body>.*?)\s*"
    r"\(resource:\s*(?P<resource>[^)]+)\)\s*$"
)


# ---------- conftest invocation + parsing ----------

def run_conftest(policy_dir: Path, bundle: Path) -> list:
    completed = subprocess.run(
        ["conftest", "test",
         "--policy", str(policy_dir),
         "--all-namespaces",
         "--output", "json",
         str(bundle)],
        capture_output=True,
        text=True,
        check=False,
    )
    if not completed.stdout.strip():
        sys.stderr.write(completed.stderr)
        sys.stderr.write(f"\nERROR: conftest produced no JSON output (exit {completed.returncode}).\n")
        sys.exit(2)
    return json.loads(completed.stdout)


def parse_finding(failure: dict) -> dict:
    msg = failure.get("msg", "")
    m = MSG_RE.match(msg)
    if not m:
        sys.stderr.write(f"ERROR: deny message does not match required format:\n  {msg!r}\n")
        sys.stderr.write("Expected: [<id>/<sev>] <body> (resource: <path>)\n")
        sys.exit(2)
    return {
        "rule_id": m.group("id"),
        "severity": m.group("sev").capitalize(),
        "body": m.group("body"),
        "resource": m.group("resource"),
    }


def collect_findings(conftest_output: list) -> list:
    findings = []
    for result in conftest_output:
        for failure in result.get("failures") or []:
            findings.append(parse_finding(failure))
    return findings


def join_with_catalog(findings: list, catalog: dict) -> list:
    enriched = []
    for f in findings:
        cat = catalog.get(f["rule_id"])
        if cat is None:
            sys.stderr.write(
                f"ERROR: finding for rule {f['rule_id']} has no catalog entry. "
                f"Add it to dab.catalog.yaml.\n"
            )
            sys.exit(2)
        if cat.get("severity") and cat["severity"] != f["severity"]:
            sys.stderr.write(
                f"WARNING: severity drift for {f['rule_id']}: rule emits {f['severity']}, "
                f"catalog says {cat['severity']}. Reporting rule severity.\n"
            )
        enriched.append({
            "rule_id":    f["rule_id"],
            "severity":   f["severity"],
            "body":       f["body"],
            "resource":   f["resource"],
            "title":      cat.get("title", f["rule_id"]),
            "why":        (cat.get("why") or "").strip(),
            "fix":        (cat.get("fix") or "").strip(),
            "notes":      (cat.get("notes") or "").strip(),
            "references": cat.get("references", []) or [],
        })
    return enriched


# ---------- exceptions / waivers ----------

def pipeline_today() -> date:
    """Prefer orchestrator-provided timestamp over runner-local clock."""
    for var in ("CI_PIPELINE_CREATED_AT", "GITHUB_RUN_STARTED_AT"):
        v = os.environ.get(var)
        if v:
            return datetime.fromisoformat(v.rstrip("Z")).date()
    return datetime.now(timezone.utc).date()


def load_exceptions(path: Path | None) -> list:
    if path is None:
        return []
    if not path.exists():
        sys.stderr.write(f"ERROR: --exceptions path not found: {path}\n")
        sys.exit(2)
    data = yaml.safe_load(path.read_text()) or []
    if not isinstance(data, list):
        sys.stderr.write(f"ERROR: {path} must be a top-level list of exception entries.\n")
        sys.exit(2)
    return data


def waiver_matches(finding: dict, exception: dict) -> bool:
    """Match a finding against a waiver. Glob semantics on `resource`:
       *      matches any character sequence
       [*]    matches any array index (e.g. [0], [12])
       Any other character is literal (square brackets, dots included)."""
    if exception.get("rule_id") != finding["rule_id"]:
        return False
    pattern = exception.get("resource") or "*"
    parts: list = []
    i = 0
    while i < len(pattern):
        if pattern[i:i+3] == "[*]":
            parts.append(r"\[\d+\]")
            i += 3
        elif pattern[i] == "*":
            parts.append(r".*")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.fullmatch("".join(parts), finding["resource"]) is not None


def triage(
    findings: list,
    exceptions: list,
    today: date,
    no_waive_critical: bool,
) -> tuple[list, list, list]:
    """Returns (active, waived, unused_exceptions). Expired waivers are folded
    into 'active' with a leading [EXPIRED-WAIVER] marker so they fail the gate."""
    active, waived, expired = [], [], []
    used_ids: set = set()

    for f in findings:
        match = next((e for e in exceptions if waiver_matches(f, e)), None)
        if match is None:
            active.append(f)
            continue
        if no_waive_critical and f["severity"] == "Critical":
            blocked = {**f, "body": f["body"] + " [WAIVER-REJECTED critical]"}
            active.append(blocked)
            continue
        try:
            expires = date.fromisoformat(str(match.get("expires", "")))
        except ValueError:
            sys.stderr.write(
                f"ERROR: exception for {f['rule_id']} has invalid 'expires' field: "
                f"{match.get('expires')!r}\n"
            )
            sys.exit(2)
        days_remaining = (expires - today).days
        enriched = {
            **f,
            "exception": match,
            "days_remaining": days_remaining,
            "expires": expires.isoformat(),
        }
        used_ids.add(id(match))
        if days_remaining < 0:
            expired.append(enriched)
        else:
            waived.append(enriched)

    unused = [e for e in exceptions if id(e) not in used_ids]

    for f in expired:
        approver = f["exception"].get("approver", "?")
        marker = f"[EXPIRED-WAIVER approved-by={approver} expires={f['expires']}] "
        active.append({**f, "body": marker + f["body"]})

    return active, waived, unused


def severity_counts(findings: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


# ---------- markdown ----------

def render_markdown(active: list, waived: list, unused: list, counts: dict) -> str:
    if not active and not waived and not unused:
        return "# DAB pre-deploy policy: PASS\n\nAll rules passed.\n"

    summary_parts = []
    if active:
        active_summary = ", ".join(
            f"{counts[s]} {s}" for s in ("Critical", "High", "Medium", "Low") if counts[s]
        )
        summary_parts.append(f"{len(active)} active ({active_summary})")
    if waived:
        summary_parts.append(f"{len(waived)} waived")
    if unused:
        summary_parts.append(f"{len(unused)} unused exceptions")

    lines = [f"# DAB pre-deploy policy: {' · '.join(summary_parts)}", ""]

    if active:
        grouped = {s: [] for s in SEVERITY_ORDER}
        for f in active:
            grouped[f["severity"]].append(f)
        for sev in ("Critical", "High", "Medium", "Low"):
            if not grouped[sev]:
                continue
            lines.append(f"## {SEVERITY_LABEL[sev]} ({len(grouped[sev])})")
            lines.append("")
            for f in grouped[sev]:
                lines.append(f"### {f['rule_id']} — {f['title']}")
                lines.append("")
                lines.append(f"**Resource:** `{f['resource']}`")
                lines.append("")
                lines.append(f"**Detection:** {f['body']}")
                lines.append("")
                if f.get("why"):
                    lines.append("**Why:**")
                    lines.append("")
                    lines.append(f["why"])
                    lines.append("")
                if f.get("fix"):
                    lines.append("**Fix:**")
                    lines.append("")
                    lines.append(f["fix"])
                    lines.append("")
                if f.get("notes"):
                    lines.append("**Notes:**")
                    lines.append("")
                    lines.append(f["notes"])
                    lines.append("")
                refs = f.get("references") or []
                if refs:
                    lines.append("**References:**")
                    lines.append("")
                    for ref in refs:
                        lines.append(f"- {ref}")
                    lines.append("")

    if waived:
        lines.append(f"## Waived ({len(waived)})")
        lines.append("")
        lines.append("These findings have an active, unexpired exception.")
        lines.append("")
        for f in waived:
            ex = f["exception"]
            lines.append(f"- **{f['rule_id']}** `{f['resource']}`")
            lines.append(
                f"  - waived by `{ex.get('approver', '?')}` on `{ex.get('approved', '?')}`, "
                f"expires `{f['expires']}` ({f['days_remaining']} days remaining)"
            )
            if ex.get("ticket"):
                lines.append(f"  - ticket: {ex['ticket']}")
            reason = (ex.get("reason") or "").strip().replace("\n", " ")
            if reason:
                lines.append(f"  - reason: {reason}")
        lines.append("")

    if unused:
        lines.append(f"## Unused exceptions ({len(unused)})")
        lines.append("")
        lines.append("These exceptions did not match any finding. Consider removing.")
        lines.append("")
        for ex in unused:
            lines.append(
                f"- `{ex.get('rule_id', '?')}` `{ex.get('resource', '*')}` "
                f"(approver: {ex.get('approver', '?')})"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# ---------- junit ----------

def render_junit(active: list, waived: list) -> str:
    total = len(active) + len(waived)
    suite = ET.Element("testsuite", {
        "name": "DAB pre-deploy policy",
        "tests": str(total),
        "failures": str(len(active)),
        "skipped": str(len(waived)),
    })
    for f in active:
        case = ET.SubElement(suite, "testcase", {
            "name": f"{f['rule_id']}: {f['title']}",
            "classname": f"dab.{f['severity']}",
        })
        body = (
            f"[{f['severity']}] {f['title']}\n"
            f"Resource: {f['resource']}\n"
            f"Detection: {f['body']}\n\n"
            f"Why:\n{f.get('why', '')}\n\n"
            f"Fix:\n{f.get('fix', '')}\n"
        )
        failure = ET.SubElement(case, "failure", {"type": f["severity"], "message": f["title"]})
        failure.text = body
    for f in waived:
        ex = f["exception"]
        case = ET.SubElement(suite, "testcase", {
            "name": f"{f['rule_id']}: {f['title']}",
            "classname": f"dab.{f['severity']}",
        })
        skipped = ET.SubElement(case, "skipped", {
            "message": f"Waived by {ex.get('approver', '?')} until {f['expires']}",
        })
        skipped.text = (
            f"Resource: {f['resource']}\n"
            f"Reason: {(ex.get('reason') or '').strip()}\n"
            f"Approver: {ex.get('approver', '?')}\n"
            f"Expires: {f['expires']} ({f['days_remaining']} days remaining)\n"
            f"Ticket: {ex.get('ticket', '')}\n"
        )
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suite, encoding="unicode")


# ---------- json ----------

def render_json(active: list, waived: list, unused: list, counts: dict) -> str:
    return json.dumps({
        "summary": counts,
        "totals": {
            "active": len(active),
            "waived": len(waived),
            "unused_exceptions": len(unused),
        },
        "active": active,
        "waived": waived,
        "unused_exceptions": unused,
    }, indent=2, default=str)


# ---------- sarif ----------

def _sarif_rule(rule_id: str, entry: dict) -> dict:
    severity = entry.get("severity", "Medium")
    why = (entry.get("why") or "").strip()
    fix = (entry.get("fix") or "").strip()
    notes = (entry.get("notes") or "").strip()
    notes_text = f"\n\nNotes: {notes}" if notes else ""
    notes_md = f"\n\n**Notes:**\n\n{notes}" if notes else ""
    rule = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": entry.get("title", rule_id)},
        "fullDescription": {"text": why or entry.get("title", rule_id)},
        "help": {
            "text":     f"Why: {why}\n\nFix: {fix}{notes_text}".strip(),
            "markdown": f"**Why:**\n\n{why}\n\n**Fix:**\n\n{fix}{notes_md}".strip(),
        },
        "defaultConfiguration": {"level": SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")},
        "properties": {
            "security-severity": SEVERITY_TO_SECURITY_SEVERITY.get(severity, "5.0"),
            "tags": ["security", "databricks", "dab"],
        },
    }
    refs = entry.get("references") or []
    http_refs = [r for r in refs if isinstance(r, str) and r.startswith("http")]
    if http_refs:
        rule["helpUri"] = http_refs[0]
    return rule


def _sarif_result(f: dict, rule_index: dict, suppressed: bool = False) -> dict:
    result = {
        "ruleId": f["rule_id"],
        "ruleIndex": rule_index.get(f["rule_id"], -1),
        "level": SEVERITY_TO_SARIF_LEVEL.get(f["severity"], "warning"),
        "message": {"text": f["body"]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "databricks.yml"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [
                    {"fullyQualifiedName": f["resource"], "kind": "value"},
                ],
            }
        ],
        "properties": {
            "security-severity": SEVERITY_TO_SECURITY_SEVERITY.get(f["severity"], "5.0"),
        },
    }
    if suppressed and "exception" in f:
        ex = f["exception"]
        result["suppressions"] = [{
            "kind": "external",
            "state": "accepted",
            "justification": (
                f"Waived by {ex.get('approver', '?')} until {f['expires']}. "
                f"Reason: {(ex.get('reason') or '').strip()}"
            ),
        }]
    return result


def render_sarif(active: list, waived: list, catalog: dict) -> str:
    rules = [_sarif_rule(rid, catalog[rid]) for rid in sorted(catalog)]
    rule_index = {r["id"]: i for i, r in enumerate(rules)}
    results = [_sarif_result(f, rule_index) for f in active]
    results += [_sarif_result(f, rule_index, suppressed=True) for f in waived]
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dab-policy",
                        "informationUri": "https://docs.databricks.com/aws/en/dev-tools/bundles/",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


# ---------- io ----------

def write_output(path: Path | None, content: str) -> None:
    if path is None:
        return
    path.write_text(content)


# ---------- main ----------

def main() -> int:
    parser = argparse.ArgumentParser(description="DAB pre-deploy policy reporter")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--exceptions", type=Path,
                        help="Optional waiver file (policy/exceptions.yaml)")
    parser.add_argument("--no-waive-critical", action="store_true",
                        help="Refuse to apply waivers to Critical findings")
    parser.add_argument("--strict-waivers", action="store_true",
                        help="Fail if any exception did not match a finding")
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--json", dest="json_out", type=Path)
    parser.add_argument("--sarif", type=Path)
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
    )
    args = parser.parse_args()

    catalog = yaml.safe_load(args.catalog.read_text()) or {}
    exceptions = load_exceptions(args.exceptions)
    today = pipeline_today()

    findings = join_with_catalog(
        collect_findings(run_conftest(args.policy, args.bundle)),
        catalog,
    )
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["rule_id"], f["resource"]))

    active, waived, unused = triage(findings, exceptions, today, args.no_waive_critical)
    counts = severity_counts(active)

    write_output(args.markdown, render_markdown(active, waived, unused, counts))
    write_output(args.junit,    render_junit(active, waived))
    write_output(args.json_out, render_json(active, waived, unused, counts))
    write_output(args.sarif,    render_sarif(active, waived, catalog))

    if not (args.markdown or args.junit or args.json_out or args.sarif):
        sys.stdout.write(render_markdown(active, waived, unused, counts))

    exit_code = 0
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on.capitalize()]
        breach = [f for f in active if SEVERITY_ORDER[f["severity"]] >= threshold]
        if breach:
            sys.stderr.write(
                f"\nFAIL: {len(breach)} active finding(s) at or above severity '{args.fail_on}'.\n"
            )
            exit_code = 1

    if args.strict_waivers and unused:
        sys.stderr.write(
            f"\nFAIL: {len(unused)} unused exception(s). "
            f"Remove them from the waiver file.\n"
        )
        exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
